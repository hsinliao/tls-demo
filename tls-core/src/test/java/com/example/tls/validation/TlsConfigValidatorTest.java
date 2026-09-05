package com.example.tls.validation;

import com.example.tls.certificate.KeyStoreLoader;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.EndpointRole;
import com.example.tls.config.StoreConfig;
import com.example.tls.config.TlsConfig;
import com.example.tls.context.JsseCapabilities;
import com.example.tls.exception.TlsCertificateException;
import com.example.tls.exception.TlsConfigurationException;
import com.example.tls.testing.TestCertificates;
import com.example.tls.testing.TestTls;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TlsConfigValidatorTest {

    private final JsseCapabilities capabilities = JsseCapabilities.probe();

    @Test
    void emptyProtocolsAreRejected() {
        TlsConfig config = TlsConfig.builder()
                .protocols(List.of())
                .build();
        TlsConfigurationException error = assertThrows(TlsConfigurationException.class,
                () -> TlsConfigValidator.validate(config, EndpointRole.SERVER,
                        TestTls.passwords(), capabilities));
        assertTrue(error.getMessage().contains("At least one TLS protocol"));
    }

    @Test
    void unsupportedLegacyProtocolIsRejectedWithoutDowngrade() {
        TlsConfig config = TlsConfig.builder()
                .protocols("TLSv1.1")
                .build();
        TlsConfigurationException error = assertThrows(TlsConfigurationException.class,
                () -> TlsConfigValidator.validate(config, EndpointRole.SERVER,
                        TestTls.passwords(), capabilities));
        assertTrue(error.getMessage().contains("TLSv1.1"));
        assertTrue(error.getMessage().contains("not allowed"));
    }

    @Test
    void zeroTimeoutIsRejected() {
        TlsConfig config = TlsConfig.builder()
                .handshakeTimeout(Duration.ZERO)
                .build();
        assertThrows(TlsConfigurationException.class,
                () -> TlsConfigValidator.validate(config, EndpointRole.SERVER,
                        TestTls.passwords(), capabilities));
    }

    @Test
    void serverWithoutKeyStoreFailsFast() {
        TlsConfig config = TlsConfig.builder()
                .clientAuthentication(ClientAuthMode.NONE)
                .trustStore(TestTls.trustStore(Path.of("does-not-matter.p12")))
                .build();
        TlsConfigurationException error = assertThrows(TlsConfigurationException.class,
                () -> TlsConfigValidator.validate(config, EndpointRole.SERVER,
                        TestTls.passwords(), capabilities));
        assertTrue(error.getMessage().contains("keyStore"));
    }

    @Test
    void needModeWithoutServerTrustStoreFailsFast() {
        TlsConfig config = TlsConfig.builder()
                .keyStore(StoreConfig.of(Path.of("does-not-matter.p12"), "TLS_KEYSTORE_PASSWORD"))
                .clientAuthentication(ClientAuthMode.NEED)
                .build();
        TlsConfigurationException error = assertThrows(TlsConfigurationException.class,
                () -> TlsConfigValidator.validate(config, EndpointRole.SERVER,
                        TestTls.passwords(), capabilities));
        assertTrue(error.getMessage().contains("NEED"));
    }

    @Test
    void clientWithoutTrustStoreFailsFast() {
        TlsConfig config = TlsConfig.builder()
                .build();
        TlsConfigurationException error = assertThrows(TlsConfigurationException.class,
                () -> TlsConfigValidator.validate(config, EndpointRole.CLIENT,
                        TestTls.passwords(), capabilities));
        assertTrue(error.getMessage().contains("trustStore"));
    }

    @Test
    void expiredCertificateFailsStartupValidation() {
        TestCertificates certs = TestCertificates.instance();
        TlsConfig config = TestTls.serverConfig(
                "expired", List.of("TLSv1.3", "TLSv1.2"),
                ClientAuthMode.NONE, List.of(), certs.expiredServerP12(), null);
        TlsCertificateException error = assertThrows(TlsCertificateException.class,
                () -> TlsConfigValidator.validate(config, EndpointRole.SERVER,
                        TestTls.passwords(), capabilities));
        assertTrue(error.getMessage().toLowerCase().contains("expired"));
    }
}
