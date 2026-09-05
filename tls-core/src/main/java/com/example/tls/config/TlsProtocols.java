package com.example.tls.config;

import java.util.List;

/**
 * Protocol names used by the JDK 17 JSSE {@code SSLParameters}. TLS 1.2 and
 * TLS 1.3 are the only protocols this foundation supports; other protocol
 * versions fail configuration validation.
 */
public final class TlsProtocols {

    public static final String TLS_1_2 = "TLSv1.2"; // JDK SSLParameters 使用的协议名
    public static final String TLS_1_3 = "TLSv1.3"; // JDK SSLParameters 使用的协议名

    /** Both protocols, TLS 1.3 preferred by JSSE. */
    public static final List<String> DEFAULT = List.of(TLS_1_3, TLS_1_2);

    private TlsProtocols() {
    }
}
