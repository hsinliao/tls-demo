package com.example.tls.validation;

import com.example.tls.certificate.CertificateUtils;
import com.example.tls.certificate.KeyStoreLoader;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.EndpointRole;
import com.example.tls.config.StoreConfig;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;
import com.example.tls.context.JsseCapabilities;
import com.example.tls.exception.TlsConfigurationException;
import com.example.tls.security.PasswordProvider;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Fail-fast validation of a {@link TlsConfig}. Every problem that can be
 * detected before the first connection is detected here: protocol policy,
 * cipher-suite policy, store existence/type, private-key entries, certificate
 * expiry, and role-specific EKU.
 */
public final class TlsConfigValidator {

    // 本基础组件只放行 TLSv1.2/TLSv1.3；其它协议即使 JSSE “支持”也拒绝配置。
    private static final Set<String> ALLOWED_PROTOCOLS =
            Set.of(TlsProtocols.TLS_1_2, TlsProtocols.TLS_1_3);

    // 启动期告警走 JDK 自带 java.util.logging，避免核心库引入第三方日志依赖。
    private static final java.util.logging.Logger LOG =
            java.util.logging.Logger.getLogger(TlsConfigValidator.class.getName());

    private TlsConfigValidator() {
    }

    /**
     * Full validation including loading and inspecting the configured stores.
     * Role-independent policy checks run first, then role-specific structural
     * checks, then certificate material checks.
     */
    public static ValidatedStores validate(TlsConfig config, EndpointRole role,
                                           PasswordProvider passwords, JsseCapabilities capabilities) {
        if (config == null) {
            throw new TlsConfigurationException("TlsConfig must not be null");
        }
        if (role == null) {
            throw new TlsConfigurationException("EndpointRole must not be null");
        }
        if (passwords == null) {
            throw new TlsConfigurationException("PasswordProvider must not be null");
        }

        validateTimeouts(config);
        validateProtocols(config, capabilities);
        TlsCipherSuitePolicy.resolve(config.protocols(), config.cipherSuites(), capabilities);
        validateRoleStructure(config, role);
        KeyStore identityStore = validateLocalIdentityStore(config, role, passwords);
        KeyStore trustStore = validateTrustStore(config, role, passwords);
        return new ValidatedStores(identityStore, trustStore);
    }

    private static void validateTimeouts(TlsConfig config) {
        requirePositive(config.connectTimeout(), "connectTimeout");
        requirePositive(config.handshakeTimeout(), "handshakeTimeout");
        requirePositive(config.socketTimeout(), "socketTimeout");
    }

    private static void requirePositive(Duration duration, String field) {
        if (duration == null || duration.isNegative() || duration.isZero()) {
            throw new TlsConfigurationException(
                    field + " must be a positive duration (got " + safeDuration(duration) + ")");
        }
    }

    private static String safeDuration(Duration duration) {
        return duration == null ? "null" : duration.toMillis() + "ms";
    }

    private static void validateProtocols(TlsConfig config, JsseCapabilities capabilities) {
        // 协议策略：宁可启动失败，也不允许隐式降级到 TLS1.0/1.1/SSLv3。
        List<String> protocols = config.protocols();
        if (protocols.isEmpty()) {
            throw new TlsConfigurationException(
                    "At least one TLS protocol must be configured. Allowed: " + ALLOWED_PROTOCOLS);
        }

        Set<String> seen = new HashSet<>();
        for (String protocol : protocols) {
            if (protocol == null || protocol.isBlank()) {
                throw new TlsConfigurationException("TLS protocol names must not be blank");
            }
            if (!seen.add(protocol)) {
                throw new TlsConfigurationException("Duplicate TLS protocol '" + protocol + "'");
            }
            if (!ALLOWED_PROTOCOLS.contains(protocol)) {
                throw new TlsConfigurationException(
                        "TLS protocol '" + protocol + "' is not allowed. This foundation supports only "
                                + ALLOWED_PROTOCOLS + " (automatic downgrade is never performed).");
            }
            if (!capabilities.supportedProtocols().contains(protocol)) {
                throw new TlsConfigurationException(
                        "TLS protocol '" + protocol + "' is not supported by the current JDK JSSE provider. "
                                + "Supported protocols: " + capabilities.supportedProtocols());
            }
        }
    }

    private static void validateRoleStructure(TlsConfig config, EndpointRole role) {
        ClientAuthMode mode = config.clientAuthentication().mode();
        // 角色级 store 结构检查必须早于文件加载：
        // 缺 KeyStore/TrustStore 属于配置错误，与磁盘上是否存在证书无关。
        if (role == EndpointRole.SERVER && config.keyStore() == null) {
            throw new TlsConfigurationException(
                    "A TLS server requires a keyStore containing its private key and certificate chain.");
        }
        if (role == EndpointRole.CLIENT && config.trustStore() == null) {
            throw new TlsConfigurationException(
                    "A TLS client requires a trustStore to verify the server certificate. "
                            + "Trust-all is not supported.");
        }
        if (role == EndpointRole.SERVER && mode == ClientAuthMode.NEED && config.trustStore() == null) {
            // mTLS 的硬性前提：服务端必须能验证客户端证书。
            throw new TlsConfigurationException(
                    "clientAuthentication.mode=NEED requires a trustStore so the server can validate "
                            + "client certificates.");
        }
        if (role == EndpointRole.SERVER && mode == ClientAuthMode.WANT && config.trustStore() == null) {
            // WANT 允许匿名客户端，但“出示了证书”的客户端仍会被校验；
            // 无 TrustStore 时 TlsContextFactory 会使用空信任锚，避免悄悄回退到 JVM 全局 cacerts。
            LOG.warning("clientAuthentication.mode=WANT is configured without a trustStore. "
                    + "Clients that present a certificate will be rejected (no trust anchors).");
        }
        if (!config.hostnameVerificationEnabled()) {
            LOG.warning("Hostname verification is disabled for '" + config.name()
                    + "'. This must never be used outside controlled tests/dev environments.");
        }
    }

    private static KeyStore validateLocalIdentityStore(TlsConfig config, EndpointRole role,
                                                       PasswordProvider passwords) {
        StoreConfig keyStore = config.keyStore();
        if (keyStore == null) {
            return null;
        }
        String description = (role == EndpointRole.SERVER ? "server" : "client") + " key store";
        KeyStore store = KeyStoreLoader.loadStore(keyStore, description, passwords);
        // 只允许唯一私钥条目（或通过 alias 显式选择），防止误把 TrustStore 当身份库加载。
        String alias = KeyStoreLoader.findKeyEntryAlias(store, keyStore.alias());
        KeyStoreLoader.PrivateKeyEntryDetails details =
                KeyStoreLoader.privateKeyEntry(store, alias, passwords, keyStore);

        validateChain(details.chain(), description, role);
        return store;
    }

    private static KeyStore validateTrustStore(TlsConfig config, EndpointRole role,
                                               PasswordProvider passwords) {
        StoreConfig trustStore = config.trustStore();
        if (trustStore == null) {
            return null;
        }
        String description = (role == EndpointRole.SERVER ? "server" : "client") + " trust store";
        KeyStore store = KeyStoreLoader.loadStore(trustStore, description, passwords);
        List<X509Certificate> anchors = KeyStoreLoader.trustedCertificates(store);
        // 信任锚过期会导致所有新握手必然失败，因此启动时就 fail-fast；
        // 30 天内到期的锚提前告警，给 CA 轮换留出时间。
        Instant now = Instant.now();
        for (X509Certificate anchor : anchors) {
            CertificateUtils.assertNotExpired(anchor, "Trust anchor '" + anchor.getSubjectX500Principal() + "'", now);
            warnIfExpiring(anchor, "Trust anchor '" + anchor.getSubjectX500Principal() + "'", now);
        }
        return store;
    }

    private static void validateChain(List<X509Certificate> chain, String description, EndpointRole role) {
        Instant now = Instant.now();
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate certificate = chain.get(i);
            String label = description + " certificate '" + certificate.getSubjectX500Principal() + "'";
            CertificateUtils.assertNotExpired(certificate, label, now);
            warnIfExpiring(certificate, label, now);
            if (i == 0) {
                CertificateUtils.assertValidForUsage(certificate, role, label);
            }
        }
    }

    private static void warnIfExpiring(X509Certificate certificate, String description, Instant now) {
        if (CertificateUtils.expiresWithin(certificate, CertificateUtils.EXPIRY_WARNING_WINDOW, now)) {
            LOG.warning(description + " expires in "
                    + CertificateUtils.timeUntilExpiry(certificate, now).toDays()
                    + " day(s). Rotate it before expiry.");
        }
    }
}
