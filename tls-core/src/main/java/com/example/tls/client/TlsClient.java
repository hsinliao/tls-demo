package com.example.tls.client;

import com.example.tls.config.EndpointRole;
import com.example.tls.config.TlsConfig;
import com.example.tls.connection.TlsConnection;
import com.example.tls.connection.TlsSocketConfigurator;
import com.example.tls.connection.TlsSocketConnection;
import com.example.tls.context.DefaultTlsContextProvider;
import com.example.tls.exception.TlsConnectionException;
import com.example.tls.exception.TlsHandshakeException;
import com.example.tls.observability.TlsHandshakeObserver;
import com.example.tls.observability.TlsMetrics;
import com.example.tls.security.PasswordProvider;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;

/**
 * TLS client wrapper. A single client instance holds one validated
 * {@link javax.net.ssl.SSLContext} and can open many connections.
 */
public final class TlsClient implements AutoCloseable {

    private final TlsConfig config;              // 客户端 TLS 配置（含超时/协议/信任库）
    private final List<TlsHandshakeObserver> observers; // 握手观测者
    private final TlsMetrics metrics;                   // 内置握手计数（始终可用）
    private final DefaultTlsContextProvider contextProvider; // 实例隔离的 SSLContext

    private TlsClient(Builder builder) {
        this.config = builder.config;
        this.metrics = TlsMetrics.create();
        List<TlsHandshakeObserver> effectiveObservers = new java.util.ArrayList<>(builder.observers);
        effectiveObservers.add(metrics);
        this.observers = List.copyOf(effectiveObservers);
        this.contextProvider =
                new DefaultTlsContextProvider(config, builder.passwords, EndpointRole.CLIENT);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Resolves {@code host} and connects using the resolved address.
     * {@code host} is used for SNI and HTTPS endpoint identification.
     */
    public TlsConnection connect(String host, int port) {
        InetSocketAddress address = new InetSocketAddress(host, port);
        if (address.isUnresolved()) {
            throw new TlsConnectionException("Unable to resolve TLS peer host '" + host + "'");
        }
        return connectTo(host, address);
    }

    /**
     * Connects to an explicit resolved address while still identifying the peer
     * as {@code peerHost}. Kept public for test scenarios such as hostname
     * mismatch tests; normal callers should use {@link #connect(String, int)}.
     */
    public TlsConnection connectTo(String peerHost, InetSocketAddress address) {
        try {
            // 连接过程拆为：TCP connect（connectTimeout）→ 配置 SSLParameters →
            // startHandshake（handshakeTimeout）→ 切换读超时（socketTimeout）。
            SSLSocket ssl =
                    TlsSocketConfigurator.connectClient(contextProvider.current(), peerHost, address);
            return TlsSocketConnection.establish(
                    ssl, EndpointRole.CLIENT, peerHost, address.getPort(),
                    config.handshakeTimeout(), config.socketTimeout(), observers);
        } catch (TlsHandshakeException e) {
            throw e;
        } catch (IOException | TlsConnectionException e) {
            throw new TlsConnectionException(
                    "Unable to connect to TLS peer " + peerHost + ":" + address.getPort()
                            + ": " + e.getMessage(), e);
        }
    }

    public TlsConfig config() {
        return config;
    }

    /** 内置线程安全握手指标。 */
    public TlsMetrics metrics() {
        return metrics;
    }

    @Override
    public void close() {
        // An SSLContext owns no OS resources that require explicit release.
    }

    public static final class Builder {
        private TlsConfig config;                    // 客户端 TLS 配置（必填）
        private PasswordProvider passwords;          // 密码解析器（必填）
        private final java.util.ArrayList<TlsHandshakeObserver> observers = new java.util.ArrayList<>(); // 可多个

        private Builder() {
        }

        public Builder config(TlsConfig value) {
            this.config = value;
            return this;
        }

        public Builder passwords(PasswordProvider value) {
            this.passwords = value;
            return this;
        }

        public Builder observer(TlsHandshakeObserver value) {
            if (value != null) {
                observers.add(value);
            }
            return this;
        }

        public TlsClient build() {
            if (config == null) {
                throw new IllegalStateException("config is required");
            }
            if (passwords == null) {
                throw new IllegalStateException("passwords is required");
            }
            return new TlsClient(this);
        }
    }
}
