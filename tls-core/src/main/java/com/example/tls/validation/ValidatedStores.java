package com.example.tls.validation;

import java.security.KeyStore;

/**
 * Stores loaded and validated exactly once by {@link TlsConfigValidator}.
 * {@link com.example.tls.context.TlsContextFactory} reuses these objects to
 * build {@code KeyManagerFactory}/{@code TrustManagerFactory}, avoiding a
 * second disk read (and second password lookup) on every startup/reload.
 */
public record ValidatedStores(
        KeyStore identityStore, // 本地身份库（可能为 null：单向客户端）
        KeyStore trustStore) {  // 对端信任库（可能为 null：由工厂按模式决定）

    public static ValidatedStores none() {
        return new ValidatedStores(null, null);
    }
}
