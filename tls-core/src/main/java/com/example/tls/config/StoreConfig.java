package com.example.tls.config;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Immutable description of a key/trust store.
 *
 * <p>Two source models are supported so future FIPS/HSM/PKCS#11 integration is
 * not blocked by "everything must be a file":
 *
 * <ul>
 *   <li>File-backed stores (PKCS12/JKS/...): {@code path != null}, loaded with
 *       {@code KeyStore.load(InputStream, storePassword)};</li>
 *   <li>Provider-backed stores (for example {@code PKCS11}): {@code path == null},
 *       loaded with {@code KeyStore.load(null, tokenPin)} after
 *       {@code KeyStore.getInstance(type[, providerName])}.</li>
 * </ul>
 *
 * <p>Only the symbolic password <em>key</em> is stored in configuration; the
 * actual password/PIN is resolved at runtime through a
 * {@code com.example.tls.security.PasswordProvider}.
 */
public record StoreConfig(
        String type,             // KeyStore 类型：PKCS12 / JKS / PKCS11 / ...
        Path path,               // 文件来源路径；Provider 来源为 null
        String providerName,     // 可选：JCE Provider 名（如 SunPKCS11 的实例名）
        String passwordKey,      // store 口令或 token PIN 的“符号名”
        String keyPasswordKey,   // 私钥条目口令；null = 与 store 口令相同（Provider 通常为 null）
        String alias) {          // 可选：多私钥条目显式选择 alias

    public static final String DEFAULT_TYPE = "PKCS12";

    public StoreConfig {
        if (type == null || type.isBlank()) {
            type = DEFAULT_TYPE;
        }
        if (path != null && providerName != null) {
            throw new IllegalArgumentException(
                    "A store cannot be both file-backed (path) and provider-backed (providerName)");
        }
        Objects.requireNonNull(passwordKey, "store password key must not be null");
        if (passwordKey.isBlank()) {
            throw new IllegalArgumentException("store password key must not be blank");
        }
        if (keyPasswordKey != null && keyPasswordKey.isBlank()) {
            keyPasswordKey = null;
        }
        if (alias != null && alias.isBlank()) {
            alias = null;
        }
    }

    /** 文件来源（默认 PKCS12）。 */
    public static StoreConfig file(Path path, String passwordKey) {
        return new StoreConfig(DEFAULT_TYPE, path, null, passwordKey, null, null);
    }

    /** 文件来源，指定 KeyStore 类型。 */
    public static StoreConfig file(String type, Path path, String passwordKey) {
        return new StoreConfig(type, path, null, passwordKey, null, null);
    }

    /** 文件来源，携带可选 keyPasswordKey 与 alias。 */
    public static StoreConfig file(String type, Path path, String passwordKey,
                                   String keyPasswordKey, String alias) {
        return new StoreConfig(type, path, null, passwordKey, keyPasswordKey, alias);
    }

    /** Provider 来源（无文件）：例如 {@code PKCS11} 类型 + HSM provider 实例名。 */
    public static StoreConfig provider(String type, String providerName, String passwordKey) {
        return new StoreConfig(type, null, providerName, passwordKey, null, null);
    }

    /** Provider 来源，不指定 provider 实例名（让 JCE 按类型解析）。 */
    public static StoreConfig provider(String type, String passwordKey) {
        return new StoreConfig(type, null, null, passwordKey, null, null);
    }

    /** 兼容旧 API 的别名：文件来源，默认 PKCS12。 */
    public static StoreConfig of(Path path, String passwordKey) {
        return file(path, passwordKey);
    }

    /** 兼容旧 API 的别名：文件来源。 */
    public static StoreConfig of(String type, Path path, String passwordKey) {
        return file(type, path, passwordKey);
    }

    public boolean isFileBased() {
        return path != null;
    }

    public boolean isProviderBased() {
        return path == null;
    }

    public StoreConfig withType(String newType) {
        return new StoreConfig(newType, path, providerName, passwordKey, keyPasswordKey, alias);
    }

    public StoreConfig withAlias(String newAlias) {
        return new StoreConfig(type, path, providerName, passwordKey, keyPasswordKey, newAlias);
    }

    /**
     * PKCS12 通常用 store 口令保护条目；JKS 可能单独配置 key password；
     * Provider/HSM 存储通常不需要把 PIN 当作条目口令传给 KeyManagerFactory。
     */
    public String effectiveKeyPasswordKey() {
        return keyPasswordKey == null ? passwordKey : keyPasswordKey;
    }

    /** Convenience for the most common secret naming convention. */
    public static StoreConfig keyStore(Path path) {
        return file(path, SecretNames.KEYSTORE_PASSWORD);
    }

    /** Convenience for the most common secret naming convention. */
    public static StoreConfig trustStore(Path path) {
        return file(path, SecretNames.TRUSTSTORE_PASSWORD);
    }
}
