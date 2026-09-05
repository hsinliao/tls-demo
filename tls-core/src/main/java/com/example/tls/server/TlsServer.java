package com.example.tls.server;

import com.example.tls.config.EndpointRole;
import com.example.tls.config.TlsConfig;
import com.example.tls.connection.TlsSocketConfigurator;
import com.example.tls.connection.TlsSocketConnection;
import com.example.tls.context.DefaultTlsContextProvider;
import com.example.tls.context.TlsContext;
import com.example.tls.context.TlsContextProvider;
import com.example.tls.exception.TlsConnectionException;
import com.example.tls.exception.TlsHandshakeException;
import com.example.tls.exception.TlsInitializationException;
import com.example.tls.observability.TlsHandshakeObserver;
import com.example.tls.observability.TlsMetrics;
import com.example.tls.security.PasswordProvider;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * A bounded, graceful TLS server. One acceptor thread owns
 * {@code SSLServerSocket.accept()}; each accepted connection runs on a bounded
 * worker pool. No connection can occupy the main accept path indefinitely.
 */
public final class TlsServer implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(TlsServer.class.getName()); // 生命周期日志

    private final Supplier<TlsConfig> configSupplier; // 供 provider 在 reload 时读取新配置
    private final PasswordProvider passwords;        // 密码解析器（不保存明文）
    private final TlsConnectionHandler handler;      // 每个已建立连接的业务处理回调
    private final List<TlsHandshakeObserver> observers; // 握手事件观察者（脱敏）
    private final TlsMetrics metrics;                   // 内置握手计数（始终可用）
    private final TlsServerOptions options;          // 线程池/队列/宽限等运行时参数
    private final DefaultTlsContextProvider contextProvider; // 当前 SSLContext 的原子持有者

    private final Object lifecycleLock = new Object(); // start/stop/reload 互斥
    private final AtomicBoolean running = new AtomicBoolean(); // 是否在 accept
    private final ThreadPoolExecutor workers; // 有界连接处理线程池
    private final Set<TlsSocketConnection> activeConnections = ConcurrentHashMap.newKeySet(); // 已握手在途连接
    private final Set<Socket> trackedSockets = ConcurrentHashMap.newKeySet(); // 已 accept、尚未被 serve 收尾的 socket

    private volatile SSLServerSocket listener;    // 当前监听 socket（绑定固定 SSLContext）
    private volatile Thread acceptorThread;       // 唯一 accept 线程
    private volatile InetAddress boundAddress;    // 已绑定地址（reload 重建时复用）

    private TlsServer(Builder builder) {
        this.configSupplier = builder.configSupplier;
        this.passwords = builder.passwords;
        this.handler = builder.handler;
        this.metrics = TlsMetrics.create();
        List<TlsHandshakeObserver> effectiveObservers = new java.util.ArrayList<>(builder.observers);
        effectiveObservers.add(metrics);
        this.observers = List.copyOf(effectiveObservers);
        this.options = builder.options;
        this.contextProvider =
                new DefaultTlsContextProvider(configSupplier, passwords, EndpointRole.SERVER);

        ThreadFactory threadFactory = new TlsServerThreadFactory(
                "tls-server-" + contextProvider.current().config().name());
        this.workers = new ThreadPoolExecutor(
                options.workerThreads(),
                options.workerThreads(),
                60L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(options.maxQueuedConnections()),
                threadFactory,
                new ThreadPoolExecutor.AbortPolicy());
    }

    public static Builder builder() {
        return new Builder();
    }

    public TlsContextProvider contextProvider() {
        return contextProvider;
    }

    /** 内置线程安全握手指标：attempts/success/failures 及协议、套件分布。 */
    public TlsMetrics metrics() {
        return metrics;
    }

    /**
     * Rebuilds the SSLContext and, while the server is running, rebinds the
     * listening socket so new connections use the new context.
     *
     * <p>Established connections keep their original TLS context/session. On a
     * rebind failure the previous context remains active and the server is
     * restored when the same local port can be rebound.
     */
    public TlsContext reloadTlsContext() {
        synchronized (lifecycleLock) {
            SSLServerSocket currentListener = listener;
            if (!running.get() || currentListener == null) {
                // 未启动时只需要原子替换 provider 里的 context。
                return contextProvider.reload();
            }

            // 先“离线构建候选 context”，失败时旧 listener/context 分毫未动。
            TlsContext candidate = contextProvider.buildNewContext();
            int port = currentListener.getLocalPort();
            InetAddress bindAddress = this.boundAddress;

            // JSSE 的 SSLServerSocket 在创建时就绑定了 SSLContext，无法原地换证书，
            // 因此必须短暂关闭旧 listener 并在同一端口重建；已 accept 的连接是独立
            // socket，不随 listener 关闭而中断。
            stopAcceptingOnly();
            try {
                // 新 listener 绑定成功后才发布新 context，保证发布即可用。
                SSLServerSocket replacement = createBoundServerSocket(candidate, bindAddress, port);
                contextProvider.publishNewContext(candidate);
                installAcceptor(replacement, bindAddress);
                LOG.log(System.Logger.Level.INFO,
                        "TLS context reloaded for server {0} (new context id {1}); "
                                + "listener rebind on {2}:{3}; existing connections keep their old session",
                        candidate.config().name(), candidate.id(), bindAddress.getHostAddress(), port);
                return candidate;
            } catch (IOException e) {
                // 发布失败：恢复旧 listener，旧 context（provider.current()）仍未改变。
                restoreListenerAfterFailedReload(bindAddress, port);
                throw new TlsInitializationException(
                        "TLS context reload failed; the previous SSLContext remains active", e);
            }
        }
    }

    /**
     * Binds to the loopback address (safe default for demos) and starts
     * accepting.
     */
    public void start(int port) throws IOException {
        start(InetAddress.getLoopbackAddress(), port);
    }

    public void start(String bindHost, int port) throws IOException {
        start(InetAddress.getByName(bindHost), port);
    }

    public void start(InetAddress bindAddress, int port) throws IOException {
        synchronized (lifecycleLock) {
            if (running.get()) {
                throw new IllegalStateException("TLS server is already running");
            }
            TlsContext context = contextProvider.current();
            SSLServerSocket serverSocket = createBoundServerSocket(context, bindAddress, port);
            installAcceptor(serverSocket, bindAddress);
            LOG.log(System.Logger.Level.INFO,
                    "TLS server {0} listening on {1}:{2} (protocols={3}, clientAuth={4})",
                    context.config().name(), bindAddress.getHostAddress(), serverSocket.getLocalPort(),
                    context.effectiveProtocols(), context.config().clientAuthentication().mode());
        }
    }

    private SSLServerSocket createBoundServerSocket(TlsContext context,
                                                    InetAddress bindAddress, int port) throws IOException {
        SSLServerSocketFactory factory = context.serverSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket();
        serverSocket.setReuseAddress(true);
        TlsSocketConfigurator.configureServerSocket(serverSocket, context);
        try {
            serverSocket.bind(new InetSocketAddress(bindAddress, port), options.backlog());
            return serverSocket;
        } catch (IOException e) {
            closeQuietly(serverSocket);
            throw e;
        }
    }

    private void installAcceptor(SSLServerSocket serverSocket, InetAddress bindAddress) {
        this.listener = serverSocket;
        this.boundAddress = bindAddress;
        this.running.set(true);
        this.acceptorThread = new Thread(this::acceptLoop,
                "tls-server-acceptor-" + contextProvider.current().config().name());
        this.acceptorThread.start();
    }

    private void restoreListenerAfterFailedReload(InetAddress bindAddress, int port) {
        try {
            SSLServerSocket restored = createBoundServerSocket(contextProvider.current(), bindAddress, port);
            installAcceptor(restored, bindAddress);
            LOG.log(System.Logger.Level.WARNING,
                    "TLS reload failed; restored the previous listener on {0}:{1}",
                    bindAddress.getHostAddress(), port);
        } catch (IOException restoreError) {
            LOG.log(System.Logger.Level.ERROR,
                    "TLS reload failed and the previous listener could not be restored on {0}:{1}",
                    bindAddress.getHostAddress(), port, restoreError);
        }
    }

    /** Bound port; useful when the server was started with port 0. */
    public int localPort() {
        SSLServerSocket current = listener;
        return current == null ? -1 : current.getLocalPort();
    }

    public boolean isRunning() {
        return running.get();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket accepted = listener.accept();
                if (!(accepted instanceof SSLSocket sslSocket)) {
                    closeQuietly(accepted);
                    continue;
                }
                // 先登记再提交：即使 worker 队列已满/正在停机，也能在强制关闭时兜底释放。
                trackedSockets.add(sslSocket);
                try {
                    workers.execute(() -> serve(sslSocket));
                } catch (RejectedExecutionException e) {
                    trackedSockets.remove(sslSocket);
                    closeQuietly(sslSocket);
                    LOG.log(System.Logger.Level.WARNING,
                            "Connection rejected because the worker queue is full");
                }
            } catch (SocketException e) {
                if (running.get()) {
                    LOG.log(System.Logger.Level.ERROR, "Accept loop stopped unexpectedly", e);
                }
                break;
            } catch (IOException e) {
                if (running.get()) {
                    LOG.log(System.Logger.Level.ERROR, "Accept loop I/O failure", e);
                }
                break;
            }
        }
    }

    private void serve(SSLSocket sslSocket) {
        String remoteDescription = sslSocket.getInetAddress().getHostAddress()
                + ":" + sslSocket.getPort();
        TlsSocketConnection connection = null;
        try {
            TlsConfig config = contextProvider.current().config();
            connection = TlsSocketConnection.establish(
                    sslSocket, EndpointRole.SERVER, remoteDescription, sslSocket.getPort(),
                    config.handshakeTimeout(), config.socketTimeout(), observers);
            activeConnections.add(connection);
            handler.handle(connection);
        } catch (TlsHandshakeException e) {
            // Already observed and logged by observers; failed handshakes are a
            // normal part of a TLS server's operation (bad clients, mTLS denials).
            LOG.log(System.Logger.Level.DEBUG, "Handshake rejected from {0}", remoteDescription);
        } catch (TlsConnectionException e) {
            LOG.log(System.Logger.Level.DEBUG,
                    "Connection from {0} ended with I/O error: {1}", remoteDescription, e.getMessage());
        } catch (Exception e) {
            LOG.log(System.Logger.Level.WARNING,
                    "Connection handler failed for peer {0}", e);
        } finally {
            trackedSockets.remove(sslSocket);
            if (connection != null) {
                activeConnections.remove(connection);
                connection.close();
            } else {
                closeQuietly(sslSocket);
            }
        }
    }

    /** Stops accepting and waits for in-flight connections up to the grace period. */
    public void stop() {
        synchronized (lifecycleLock) {
            SSLServerSocket currentListener = listener;
            if (currentListener != null) {
                stopAcceptingOnly();
                LOG.log(System.Logger.Level.INFO, "TLS server {0} stopped accepting new connections",
                        contextProvider.current().config().name());
            } else {
                // 从未 start() 的实例也必须释放 worker 线程池。
                running.set(false);
            }

            // shutdown() 只拒绝新任务，已运行任务正常结束；
            // 之后 awaitTermination 等待宽限期，超时才强制关闭。
            workers.shutdown();
            boolean terminated = awaitTermination(workers, options.shutdownGracePeriod());
            if (!terminated) {
                LOG.log(System.Logger.Level.WARNING,
                        "Grace period elapsed; forcing remaining connections of {0} to close",
                        contextProvider.current().config().name());
                forceCloseTrackedResources();
                workers.shutdownNow();
                awaitTermination(workers, Duration.ofSeconds(1));
            }
        }
    }

    private void forceCloseTrackedResources() {
        // 同时关闭：已握手连接 + 排队中尚未执行 handler 的连接。
        activeConnections.forEach(TlsSocketConnection::close);
        trackedSockets.forEach(socket -> closeQuietly(socket));
    }

    private void stopAcceptingOnly() {
        // 只关 acceptor 与 listener；不动 worker 线程池，因此 reload 不影响在途连接。
        running.set(false);
        closeQuietly(listener);
        listener = null;
        Thread acceptor = acceptorThread;
        acceptorThread = null;
        if (acceptor != null && acceptor.isAlive()) {
            acceptor.interrupt();
            try {
                acceptor.join(1_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOG.log(System.Logger.Level.WARNING, "Interrupted while joining acceptor thread");
            }
        }
    }

    private static boolean awaitTermination(ThreadPoolExecutor executor,
                                            Duration timeout) {
        try {
            return executor.awaitTermination(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
            return false;
        }
    }

    @Override
    public void close() {
        stop();
    }

    private static void closeQuietly(ServerSocket serverSocket) {
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
            // Already closed.
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException ignored) {
            // Already closed.
        }
    }

    public static final class Builder {
        private Supplier<TlsConfig> configSupplier; // config 或 configSupplier 二选一
        private PasswordProvider passwords;        // 必填
        private TlsConnectionHandler handler;      // 必填
        private final java.util.ArrayList<TlsHandshakeObserver> observers = new java.util.ArrayList<>(); // 可多个
        private TlsServerOptions options = TlsServerOptions.defaults(); // 默认有界参数

        private Builder() {
        }

        public Builder config(TlsConfig config) {
            this.configSupplier = () -> config;
            return this;
        }

        public Builder configSupplier(Supplier<TlsConfig> configSupplier) {
            this.configSupplier = configSupplier;
            return this;
        }

        public Builder passwords(PasswordProvider value) {
            this.passwords = value;
            return this;
        }

        public Builder handler(TlsConnectionHandler value) {
            this.handler = value;
            return this;
        }

        public Builder observer(TlsHandshakeObserver value) {
            if (value != null) {
                observers.add(value);
            }
            return this;
        }

        public Builder options(TlsServerOptions value) {
            this.options = value == null ? TlsServerOptions.defaults() : value;
            return this;
        }

        public TlsServer build() {
            if (configSupplier == null) {
                throw new IllegalStateException("config or configSupplier is required");
            }
            if (passwords == null) {
                throw new IllegalStateException("passwords is required");
            }
            if (handler == null) {
                throw new IllegalStateException("handler is required");
            }
            return new TlsServer(this);
        }
    }

    private static final class TlsServerThreadFactory implements ThreadFactory {
        private final AtomicInteger sequence = new AtomicInteger(); // worker 序号
        private final String prefix; // 线程名前缀：tls-server-<name>-worker-

        private TlsServerThreadFactory(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public Thread newThread(Runnable task) {
            Thread thread = new Thread(task, prefix + "-worker-" + sequence.incrementAndGet());
            thread.setDaemon(false);
            return thread;
        }
    }
}
