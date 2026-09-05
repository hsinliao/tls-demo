package com.example.tls.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Immutable, role-independent TLS configuration.
 *
 * <p>An empty {@code cipherSuites} list means "use the current JDK 17 JSSE
 * security defaults". A non-empty list is a strict whitelist and is enforced by
 * {@code TlsCipherSuitePolicy} with fail-fast validation.
 *
 * <p>No password or private key is ever part of this object. Stores only carry
 * a symbolic password key resolved through a {@code PasswordProvider}.
 */
public record TlsConfig(
        String name,                       // 配置实例名，仅用于日志/可观测性，不含任何语义
        List<String> protocols,            // 显式协议白名单：只允许 TLSv1.2 / TLSv1.3
        List<String> cipherSuites,         // 空 = JDK 默认；非空 = 严格白名单
        ClientAuthentication clientAuthentication, // 服务端视角的 NONE/WANT/NEED
        StoreConfig keyStore,              // 本地身份库（私钥+证书链），Server 必需
        StoreConfig trustStore,            // 对端信任锚库；Client 必需，Server NEED 必需
        boolean hostnameVerificationEnabled, // Client 端 RFC6125 SAN 校验开关（默认开启）
        Duration connectTimeout,           // TCP connect 超时（仅 Client）
        Duration handshakeTimeout,         // TLS 握手超时（Client/Server 均生效）
        Duration socketTimeout,            // 握手成功后每次读操作的超时
        List<String> applicationProtocols) { // ALPN 候选协议，空表示不协商（预留）

    /** 默认 TCP 连接超时：5 秒。 */
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofMillis(5_000);
    /** 默认 TLS 握手超时：10 秒。 */
    public static final Duration DEFAULT_HANDSHAKE_TIMEOUT = Duration.ofMillis(10_000);
    /** 默认 Socket 读超时：30 秒。 */
    public static final Duration DEFAULT_SOCKET_TIMEOUT = Duration.ofMillis(30_000);

    public TlsConfig {
        name = name == null || name.isBlank() ? "tls" : name.trim();
        // 注意：cipherSuites 为空不是 bug，而是核心策略——
        // “不覆盖 SSLParameters 的 cipher suites，让 JDK 自己使用安全默认值”。
        // 这里只做防御性拷贝，绝不在此处固化一套自有默认列表。
        protocols = copy(protocols);
        cipherSuites = copy(cipherSuites);
        applicationProtocols = copy(applicationProtocols);
        clientAuthentication = clientAuthentication == null ? ClientAuthentication.NONE : clientAuthentication;
        connectTimeout = connectTimeout == null ? DEFAULT_CONNECT_TIMEOUT : connectTimeout;
        handshakeTimeout = handshakeTimeout == null ? DEFAULT_HANDSHAKE_TIMEOUT : handshakeTimeout;
        socketTimeout = socketTimeout == null ? DEFAULT_SOCKET_TIMEOUT : socketTimeout;
    }

    private static List<String> copy(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return new Builder()
                .name(name)
                .protocols(protocols)
                .cipherSuites(cipherSuites)
                .clientAuthentication(clientAuthentication)
                .keyStore(keyStore)
                .trustStore(trustStore)
                .hostnameVerificationEnabled(hostnameVerificationEnabled)
                .connectTimeout(connectTimeout)
                .handshakeTimeout(handshakeTimeout)
                .socketTimeout(socketTimeout)
                .applicationProtocols(applicationProtocols);
    }

    public static final class Builder {
        // 下面字段与 TlsConfig record 一一对应，build() 时会做防御性拷贝。
        private String name = "tls";
        private List<String> protocols = new ArrayList<>(TlsProtocols.DEFAULT); // 默认同时启用 TLS1.3/TLS1.2
        private List<String> cipherSuites = new ArrayList<>();                  // 默认空：交给 JDK
        private ClientAuthentication clientAuthentication = ClientAuthentication.NONE; // 默认单向
        private StoreConfig keyStore;        // 默认无身份库（Server 构建时校验强制提供）
        private StoreConfig trustStore;      // 默认无信任库（Client 构建时校验强制提供）
        private boolean hostnameVerificationEnabled = true; // 默认开启，禁止全局 trust-all
        private Duration connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private Duration handshakeTimeout = DEFAULT_HANDSHAKE_TIMEOUT;
        private Duration socketTimeout = DEFAULT_SOCKET_TIMEOUT;
        private List<String> applicationProtocols = new ArrayList<>(); // 默认不协商 ALPN

        private Builder() {
        }

        public Builder name(String value) {
            this.name = value;
            return this;
        }

        public Builder protocols(String... values) {
            return protocols(List.of(values));
        }

        public Builder protocols(List<String> values) {
            this.protocols = new ArrayList<>(values);
            return this;
        }

        public Builder cipherSuites(String... values) {
            return cipherSuites(List.of(values));
        }

        public Builder cipherSuites(List<String> values) {
            this.cipherSuites = values == null ? new ArrayList<>() : new ArrayList<>(values);
            return this;
        }

        public Builder clientAuthentication(ClientAuthentication value) {
            this.clientAuthentication = Objects.requireNonNull(value, "clientAuthentication");
            return this;
        }

        public Builder clientAuthentication(ClientAuthMode mode) {
            return clientAuthentication(ClientAuthentication.of(mode));
        }

        public Builder keyStore(StoreConfig value) {
            this.keyStore = value;
            return this;
        }

        public Builder trustStore(StoreConfig value) {
            this.trustStore = value;
            return this;
        }

        public Builder hostnameVerificationEnabled(boolean value) {
            this.hostnameVerificationEnabled = value;
            return this;
        }

        public Builder connectTimeout(Duration value) {
            this.connectTimeout = value;
            return this;
        }

        public Builder connectTimeoutMillis(long millis) {
            return connectTimeout(Duration.ofMillis(millis));
        }

        public Builder handshakeTimeout(Duration value) {
            this.handshakeTimeout = value;
            return this;
        }

        public Builder handshakeTimeoutMillis(long millis) {
            return handshakeTimeout(Duration.ofMillis(millis));
        }

        public Builder socketTimeout(Duration value) {
            this.socketTimeout = value;
            return this;
        }

        public Builder socketTimeoutMillis(long millis) {
            return socketTimeout(Duration.ofMillis(millis));
        }

        public Builder applicationProtocols(List<String> values) {
            this.applicationProtocols = values == null ? new ArrayList<>() : new ArrayList<>(values);
            return this;
        }

        public TlsConfig build() {
            // 构建时全部字段都会经过 record compact constructor 的防御性拷贝，
            // 因此调用方之后修改传入的 List 不会影响已生成的配置。
            return new TlsConfig(name, protocols, cipherSuites, clientAuthentication,
                    keyStore, trustStore, hostnameVerificationEnabled,
                    connectTimeout, handshakeTimeout, socketTimeout, applicationProtocols);
        }
    }
}
