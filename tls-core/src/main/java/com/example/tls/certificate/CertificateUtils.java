package com.example.tls.certificate;

import com.example.tls.config.EndpointRole;
import com.example.tls.exception.TlsCertificateException;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.List;

/**
 * Small certificate helpers used during startup validation. All PKIX path
 * building, signature verification, validity checks, and EKU enforcement during
 * real handshakes remain in the JDK JSSE trust manager.
 */
public final class CertificateUtils {

    /** 证书距过期时间小于该窗口时，启动期输出 warning（默认 30 天）。 */
    public static final Duration EXPIRY_WARNING_WINDOW = Duration.ofDays(30);

    private CertificateUtils() {
    }

    public static X509Certificate parseCertificate(InputStream in) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        } catch (CertificateException e) {
            throw new TlsCertificateException("Unable to parse X.509 certificate", e);
        }
    }

    /** How long until the certificate expires; negative means already expired. */
    public static Duration timeUntilExpiry(X509Certificate certificate, Instant now) {
        return Duration.between(now, certificate.getNotAfter().toInstant());
    }

    /**
     * Fail fast when a certificate is already expired. An expired local
     * certificate is never usable for new TLS connections.
     */
    public static void assertNotExpired(X509Certificate certificate, String description, Instant now) {
        Duration remaining = timeUntilExpiry(certificate, now);
        if (remaining.isNegative() || remaining.isZero()) {
            // 已过期证书在握手前就要暴露，而不是等第一笔流量才出现 PKIX 异常。
            throw new TlsCertificateException(
                    description + " expired at " + certificate.getNotAfter().toInstant()
                            + " (current time " + now + ")");
        }
    }

    /**
     * Returns true when the certificate will expire within the configured
     * warning window but is not yet expired.
     */
    public static boolean expiresWithin(X509Certificate certificate, Duration warningWindow, Instant now) {
        Duration remaining = timeUntilExpiry(certificate, now);
        return !remaining.isNegative()
                && remaining.compareTo(warningWindow) <= 0;
    }

    /**
     * Extended Key Usage OIDs of the certificate. An absent extension returns
     * {@code null} per RFC 5280 (any usage is then permitted by JSSE).
     */
    public static List<String> extendedKeyUsageOids(X509Certificate certificate) {
        try {
            return certificate.getExtendedKeyUsage();
        } catch (CertificateException e) {
            throw new TlsCertificateException(
                    "Unable to read Extended Key Usage of certificate '" + certificate.getSubjectX500Principal() + "'", e);
        }
    }

    /**
     * Validates role-specific EKU. When the EKU extension exists it must contain
     * the expected role usage (serverAuth for servers, clientAuth for clients);
     * an absent EKU extension is tolerated with a warning because RFC 5280 treats
     * it as unrestricted. The certificate scripts in this repo always set the
     * correct EKU explicitly.
     */
    public static void assertValidForUsage(X509Certificate certificate, EndpointRole role, String description) {
        List<String> ekus = extendedKeyUsageOids(certificate);
        if (ekus == null) {
            logWarning(description + " has no Extended Key Usage extension; RFC 5280 treats this as unrestricted. "
                    + "Prefer an explicit " + role.keyUsageDisplayName() + " EKU.");
            return;
        }
        if (!ekus.contains(role.extendedKeyUsageOid())) {
            throw new TlsCertificateException(
                    description + " is not valid for " + role.keyUsageDisplayName()
                            + ": Extended Key Usage " + sorted(ekus) + " does not contain "
                            + role.keyUsageDisplayName());
        }
        assertKeyUsageForRole(certificate, role, description);
    }

    /**
     * RFC 5280 Key Usage 启动期预检。RSA 服务端证书通常需要
     * digitalSignature 或 keyEncipherment，客户端/ECDSA 证书至少需要
     * digitalSignature；extension 缺失时交给 JSSE 握手期处理（视为不限制）。
     */
    private static void assertKeyUsageForRole(X509Certificate certificate, EndpointRole role,
                                              String description) {
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage == null) {
            return;
        }
        boolean digitalSignature = keyUsage.length > 0 && keyUsage[0];
        boolean keyEncipherment = keyUsage.length > 2 && keyUsage[2];
        boolean valid;
        if (role == EndpointRole.SERVER) {
            valid = digitalSignature || keyEncipherment;
        } else {
            valid = digitalSignature;
        }
        if (!valid) {
            throw new TlsCertificateException(
                    description + " Key Usage does not permit " + role.keyUsageDisplayName()
                            + " (expected digitalSignature"
                            + (role == EndpointRole.SERVER ? " and/or keyEncipherment" : "")
                            + ")");
        }
    }

    private static String sorted(List<String> values) {
        return String.valueOf(values.stream().sorted().toList());
    }

    private static void logWarning(String message) {
        // java.util.logging is the JDK's own logging backend used to keep the
        // core free of third-party logging dependencies.
        java.util.logging.Logger.getLogger(CertificateUtils.class.getName())
                .warning(message);
    }

}
