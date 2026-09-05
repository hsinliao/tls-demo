package com.example.tls.server;

import java.time.Duration;

/**
 * Bounded runtime knobs for {@link TlsServer}. These are server-lifecycle
 * options, deliberately separated from TLS cryptographic configuration.
 */
public record TlsServerOptions(
        int backlog,                 // ServerSocket accept 队列深度
        int workerThreads,           // 处理连接的线程数（有界池 core=max）
        int maxQueuedConnections,    // 等待 worker 的排队连接上限
        Duration shutdownGracePeriod) { // 停止时等待在途连接完成的宽限期

    /** 默认 accept backlog：50。 */
    public static final int DEFAULT_BACKLOG = 50;
    /** 默认连接处理线程数：4。 */
    public static final int DEFAULT_WORKER_THREADS = 4;
    /** 默认排队连接上限：256。 */
    public static final int DEFAULT_MAX_QUEUED_CONNECTIONS = 256;
    /** 默认优雅关闭宽限：5 秒。 */
    public static final Duration DEFAULT_SHUTDOWN_GRACE = Duration.ofSeconds(5);

    public TlsServerOptions {
        if (backlog <= 0) {
            backlog = DEFAULT_BACKLOG;
        }
        if (workerThreads <= 0) {
            workerThreads = DEFAULT_WORKER_THREADS;
        }
        if (maxQueuedConnections < 0) {
            maxQueuedConnections = 0;
        }
        if (shutdownGracePeriod == null || shutdownGracePeriod.isNegative()) {
            shutdownGracePeriod = DEFAULT_SHUTDOWN_GRACE;
        }
    }

    public static TlsServerOptions defaults() {
        return new TlsServerOptions(DEFAULT_BACKLOG, DEFAULT_WORKER_THREADS,
                DEFAULT_MAX_QUEUED_CONNECTIONS, DEFAULT_SHUTDOWN_GRACE);
    }
}
