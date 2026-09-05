package com.example.tls.context;

import com.example.tls.exception.TlsInitializationException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * Immutable snapshot of what the current JDK JSSE provider supports and enables
 * by default. The "default enabled" list is intentionally taken from
 * {@link SSLContext#getDefaultSSLParameters()} so the project inherits future
 * JDK security-policy updates instead of pinning its own list.
 */
public record JsseCapabilities(
        List<String> supportedProtocols,        // Provider 支持（但未必启用）的协议
        List<String> supportedCipherSuites,     // Provider 支持的全部套件，含被安全策略禁用的
        List<String> defaultEnabledCipherSuites, // 当前 JDK 默认“启用”的套件（策略过滤后）
        List<String> defaultProtocols) {        // 当前 JDK 默认启用协议，通常为 [TLSv1.3, TLSv1.2]

    public JsseCapabilities {
        supportedProtocols = List.copyOf(supportedProtocols);
        supportedCipherSuites = List.copyOf(supportedCipherSuites);
        defaultEnabledCipherSuites = List.copyOf(defaultEnabledCipherSuites);
        defaultProtocols = List.copyOf(defaultProtocols);
    }

    /**
     * Probes the default JSSE provider. The probe context is initialized with
     * empty manager arrays; this never installs a trust-all manager and never
     * reads the JVM-global {@code javax.net.ssl.*} stores.
     */
    public static JsseCapabilities probe() {
        try {
            // SSLContext.getSupportedSSLParameters()/getDefaultSSLParameters()
            // 在 JDK 17 中要求 context 已 init；用“空管理器数组”初始化可以
            // 避免读取 javax.net.ssl.* 全局 store，也不会安装 trust-all。
            SSLContext probe = SSLContext.getInstance("TLS");
            probe.init(new KeyManager[0], new TrustManager[0], null);
            SSLParameters supported = probe.getSupportedSSLParameters();
            SSLParameters defaults = probe.getDefaultSSLParameters();
            return new JsseCapabilities(
                    Arrays.asList(supported.getProtocols()),
                    Arrays.asList(supported.getCipherSuites()),
                    Arrays.asList(defaults.getCipherSuites()),
                    Arrays.asList(defaults.getProtocols()));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new TlsInitializationException(
                    "Unable to probe JDK JSSE capabilities for protocol 'TLS'", e);
        }
    }
}
