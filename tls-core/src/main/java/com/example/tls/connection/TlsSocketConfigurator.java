package com.example.tls.connection;

import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.TlsConfig;
import com.example.tls.context.TlsContext;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.List;

/**
 * Applies the effective {@link SSLParameters} and client-authentication mode to
 * client/server sockets. Protocol lists are always applied explicitly (never
 * downgrade silently); cipher suites are only applied for strict whitelists.
 */
public final class TlsSocketConfigurator {

    private TlsSocketConfigurator() {
    }

    public static void configureServerSocket(SSLServerSocket socket, TlsContext context) {
        SSLParameters parameters = socket.getSSLParameters();
        parameters.setProtocols(stringArray(context.effectiveProtocols()));
        if (context.cipherSuitesExplicitlyConfigured()) {
            parameters.setCipherSuites(stringArray(context.effectiveCipherSuites()));
        }
        applyApplicationProtocols(parameters, context.config().applicationProtocols());
        socket.setSSLParameters(parameters);

        ClientAuthMode mode = context.config().clientAuthentication().mode();
        // NONE/WANT/NEED 必须先同时清掉两个 flag，再按模式设置其一，
        // 避免先前 setNeedClientAuth(true) 的 socket 在复用/重建时残留状态。
        socket.setNeedClientAuth(false);
        socket.setWantClientAuth(false);
        switch (mode) {
            case NONE -> {
                // 两个 flag 均为 false：服务端完全不请求客户端证书。
            }
            // WANT = 可选认证：允许客户端“无证书完成握手”。
            case WANT -> socket.setWantClientAuth(true);
            // NEED = 强制 mTLS：客户端没有证书或证书不可信时握手失败。
            case NEED -> socket.setNeedClientAuth(true);
        }
    }

    public static void configureClientSocket(SSLSocket socket, TlsContext context) {
        SSLParameters parameters = socket.getSSLParameters();
        parameters.setProtocols(stringArray(context.effectiveProtocols()));
        if (context.cipherSuitesExplicitlyConfigured()) {
            parameters.setCipherSuites(stringArray(context.effectiveCipherSuites()));
        }
        if (context.config().hostnameVerificationEnabled()) {
            // RFC 6125 端点识别：JSSE 会拿“对端主机名”与服务器证书 SAN 比对。
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
        }
        applyApplicationProtocols(parameters, context.config().applicationProtocols());
        socket.setSSLParameters(parameters);
    }

    /**
     * Opens a TCP connection (with connect timeout), wraps it in an
     * {@link SSLSocket}, and applies client parameters. {@code peerHost} is used
     * by JSSE for SNI and endpoint identification, while the underlying address
     * can be a different resolved IP (useful for tests and proxies).
     *
     * @return an already-TCP-connected {@link SSLSocket}; the TLS handshake has
     *         not yet run
     */
    public static SSLSocket connectClient(TlsContext context, String peerHost, InetSocketAddress target)
            throws IOException {
        if (peerHost == null || peerHost.isBlank()) {
            throw new IllegalArgumentException("peerHost must not be blank");
        }
        if (target == null || target.isUnresolved()) {
            throw new IllegalArgumentException("target must be a resolved socket address");
        }

        Socket plain = null;
        SSLSocket ssl = null;
        try {
            // 先建立带 connectTimeout 的 TCP 连接，再用 createSocket(plain, peerHost,...)
            // 包装成 SSLSocket：peerHost 只参与 SNI/主机名校验，实际 IP 可来自
            // target（支持测试中“身份名 ≠ 连接 IP”的场景）。
            plain = new Socket();
            plain.connect(target, toIntTimeout(context.config().connectTimeout(), "connectTimeout"));
            ssl = (SSLSocket) context.socketFactory()
                    .createSocket(plain, peerHost, target.getPort(), true);
            plain = null; // 所有权已移交给 SSLSocket（autoClose=true）
            configureClientSocket(ssl, context);
            return ssl;
        } catch (IOException | RuntimeException e) {
            // 任何失败路径都释放已创建的 plain socket 或 ssl socket，避免连接泄漏。
            if (ssl != null) {
                try {
                    ssl.close();
                } catch (IOException ignored) {
                    // 已关闭或并发关闭。
                }
            }
            if (plain != null) {
                try {
                    plain.close();
                } catch (IOException ignored) {
                    // Best effort cleanup after a failed connect/wrap.
                }
            }
            throw e;
        }
    }

    private static void applyApplicationProtocols(SSLParameters parameters, List<String> applicationProtocols) {
        if (applicationProtocols != null && !applicationProtocols.isEmpty()) {
            // ALPN support reserved for future protocols (for example HTTP/2);
            // the demo never negotiates an application protocol by default.
            parameters.setApplicationProtocols(stringArray(applicationProtocols));
        }
    }

    private static String[] stringArray(List<String> values) {
        return values.toArray(String[]::new);
    }

    private static int toIntTimeout(Duration duration, String field) {
        try {
            return Math.toIntExact(duration.toMillis());
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(field + " is too large: " + duration.toMillis() + "ms");
        }
    }
}
