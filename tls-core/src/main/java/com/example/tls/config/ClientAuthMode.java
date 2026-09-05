package com.example.tls.config;

/**
 * Client authentication mode requested by a TLS <em>server</em>.
 *
 * <p>The values map directly to the JSSE {@code SSLSocket}/{@code SSLServerSocket}
 * semantics:
 *
 * <ul>
 *   <li>{@link #NONE} - the server never asks for a client certificate.</li>
 *   <li>{@link #WANT} - the server asks for a certificate but tolerates a client
 *       that does not present one. A presented certificate is still validated.</li>
 *   <li>{@link #NEED} - the server requires and validates a client certificate
 *       (standard mutual TLS). A client without a valid certificate fails the
 *       handshake.</li>
 * </ul>
 */
public enum ClientAuthMode {
    // NONE：服务端不请求客户端证书，也不验证任何客户端身份。
    NONE,
    // WANT：服务端会发送 CertificateRequest，但客户端无证书仍可继续握手。
    // 注意：若客户端“出示了”证书而该证书无法通过 TrustManager 校验，握手仍会失败。
    WANT,
    // NEED：标准 mTLS。客户端没有可用/被信任证书时，握手必须失败。
    NEED;

    public static ClientAuthMode parse(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Client authentication mode must not be blank");
        }
        try {
            return valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Unsupported client authentication mode '" + value + "'. Allowed: NONE, WANT, NEED", e);
        }
    }
}
