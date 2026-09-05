package com.example.tls.certificate;

import com.example.tls.config.EndpointRole;
import com.example.tls.exception.TlsCertificateException;
import com.example.tls.testing.TestCertificates;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateUtilsTest {

    @Test
    void expiredCertificateIsDetectedAndRejected() throws Exception {
        TestCertificates certs = TestCertificates.instance();
        X509Certificate expired;
        try (InputStream in = Files.newInputStream(certs.expiredServerCrt())) {
            expired = CertificateUtils.parseCertificate(in);
        }

        assertTrue(CertificateUtils.timeUntilExpiry(expired, Instant.now()).isNegative());
        TlsCertificateException error = assertThrows(TlsCertificateException.class,
                () -> CertificateUtils.assertNotExpired(expired, "server certificate", Instant.now()));
        assertTrue(error.getMessage().contains("expired"));
    }

    @Test
    void serverEkuIsReadAsExpectedOid() throws Exception {
        TestCertificates certs = TestCertificates.instance();
        X509Certificate certificate;
        try (InputStream in = Files.newInputStream(certs.expiredServerCrt())) {
            certificate = CertificateUtils.parseCertificate(in);
        }

        List<String> ekus = CertificateUtils.extendedKeyUsageOids(certificate);
        assertFalse(ekus.isEmpty());
        assertTrue(ekus.contains(EndpointRole.SERVER.extendedKeyUsageOid()));
        CertificateUtils.assertValidForUsage(certificate, EndpointRole.SERVER, "server certificate");
    }

    @Test
    void clientCertificatePassesClientRoleAndIsRejectedForServerRole() throws Exception {
        TestCertificates certs = TestCertificates.instance();
        X509Certificate client;
        try (InputStream in = Files.newInputStream(certs.clientCrt())) {
            client = CertificateUtils.parseCertificate(in);
        }

        // clientAuth EKU + digitalSignature 应通过客户端角色校验。
        CertificateUtils.assertValidForUsage(client, EndpointRole.CLIENT, "client certificate");

        // 同一张证书不能当作 serverAuth 证书使用。
        TlsCertificateException error = assertThrows(TlsCertificateException.class,
                () -> CertificateUtils.assertValidForUsage(client, EndpointRole.SERVER, "client certificate"));
        assertTrue(error.getMessage().contains("serverAuth"));
    }
}
