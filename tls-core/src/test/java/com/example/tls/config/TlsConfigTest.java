package com.example.tls.config;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TlsConfigTest {

    @Test
    void builderProvidesSecureDefaults() {
        TlsConfig config = TlsConfig.builder().build();

        assertEquals(List.of("TLSv1.3", "TLSv1.2"), config.protocols());
        assertTrue(config.cipherSuites().isEmpty(), "empty cipher list means JDK defaults");
        assertEquals(ClientAuthMode.NONE, config.clientAuthentication().mode());
        assertTrue(config.hostnameVerificationEnabled());
        assertNull(config.keyStore());
        assertNull(config.trustStore());
        assertEquals(Duration.ofMillis(5_000), config.connectTimeout());
        assertEquals(Duration.ofMillis(10_000), config.handshakeTimeout());
        assertEquals(Duration.ofMillis(30_000), config.socketTimeout());
    }

    @Test
    void configListsAreDefensivelyCopied() {
        List<String> mutable = new ArrayList<>(List.of("TLSv1.3"));
        TlsConfig config = TlsConfig.builder()
                .protocols(mutable)
                .build();

        mutable.add("TLSv1.2");
        assertEquals(List.of("TLSv1.3"), config.protocols());

        assertTrue(config.cipherSuites().isEmpty());
        assertTrue(config.cipherSuites().isEmpty());
    }

    @Test
    void configIsImmutableAndCopyWithKeepsOriginal() {
        TlsConfig original = TlsConfig.builder()
                .name("original")
                .clientAuthentication(ClientAuthMode.NONE)
                .build();

        TlsConfig rotated = TlsConfig.builder()
                .name("rotated")
                .protocols(TlsProtocols.TLS_1_3)
                .clientAuthentication(ClientAuthMode.NEED)
                .build();

        assertEquals("original", original.name());
        assertEquals(ClientAuthMode.NONE, original.clientAuthentication().mode());
        assertEquals("rotated", rotated.name());
        assertEquals(List.of("TLSv1.3"), rotated.protocols());
        assertNotSame(original, rotated);
    }

    @Test
    void aliasSelectionAndCustomStoreTypeAreRepresentable() {
        StoreConfig store = StoreConfig.of("PKCS12", java.nio.file.Path.of("certs/server.p12"),
                        "TLS_KEYSTORE_PASSWORD")
                .withAlias("server")
                .withType("JKS");

        assertEquals("JKS", store.type());
        assertEquals("server", store.alias());
        assertEquals("TLS_KEYSTORE_PASSWORD", store.passwordKey());
    }

    @Test
    void providerBackedStoreHasNoPathButKeepsPasswordKey() {
        StoreConfig provider = StoreConfig.provider("PKCS11", "SunPKCS11-HSM", "TLS_HSM_PIN");

        assertTrue(provider.isProviderBased());
        assertNull(provider.path());
        assertEquals("PKCS11", provider.type());
        assertEquals("SunPKCS11-HSM", provider.providerName());
        assertEquals("TLS_HSM_PIN", provider.passwordKey());
    }

    @Test
    void fileAndProviderSourcesAreMutuallyExclusive() {
        assertThrows(IllegalArgumentException.class,
                () -> new StoreConfig("PKCS12", java.nio.file.Path.of("server.p12"),
                        "SunPKCS11", "TLS_KEYSTORE_PASSWORD", null, null));
    }
}
