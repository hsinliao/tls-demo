package com.example.tls.validation;

import com.example.tls.config.TlsProtocols;
import com.example.tls.context.JsseCapabilities;
import com.example.tls.exception.TlsConfigurationException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TlsCipherSuitePolicyTest {

    private final JsseCapabilities capabilities = JsseCapabilities.probe();

    @Test
    void emptyConfigurationUsesJdkDefaultsAndDoesNotPinAList() {
        CipherSuitePlan plan = TlsCipherSuitePolicy.resolve(
                List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2), List.of(), capabilities);

        assertFalse(plan.explicit());
        assertFalse(plan.cipherSuites().isEmpty());
        assertEquals(capabilities.defaultEnabledCipherSuites(), plan.cipherSuites());
    }

    @Test
    void explicitSupportedTls13SuiteIsAcceptedAsStrictWhitelist() {
        List<String> suites = List.of("TLS_AES_256_GCM_SHA384");
        CipherSuitePlan plan = TlsCipherSuitePolicy.resolve(
                List.of(TlsProtocols.TLS_1_3), suites, capabilities);

        assertTrue(plan.explicit());
        assertEquals(suites, plan.cipherSuites());
    }

    @Test
    void explicitSupportedTls12SuiteIsAcceptedWhenTls12IsEnabled() {
        List<String> suites = List.of("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        CipherSuitePlan plan = TlsCipherSuitePolicy.resolve(
                List.of(TlsProtocols.TLS_1_2), suites, capabilities);

        assertTrue(plan.explicit());
        assertEquals(suites, plan.cipherSuites());
    }

    @Test
    void unsupportedSuiteFailsFast() {
        TlsConfigurationException error = assertThrows(TlsConfigurationException.class,
                () -> TlsCipherSuitePolicy.resolve(
                        List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
                        List.of("TLS_MADE_UP_CIPHER_SUITE"), capabilities));
        assertTrue(error.getMessage().contains("not supported"));
    }

    @Test
    void insecureSuiteIsRejectedBeforeAnythingElse() {
        for (String insecure : List.of("TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_NULL_SHA",
                "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA")) {
            TlsConfigurationException error = assertThrows(TlsConfigurationException.class,
                    () -> TlsCipherSuitePolicy.resolve(
                            List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
                            List.of(insecure), capabilities));
            assertTrue(error.getMessage().contains("security policy"), insecure);
        }
    }

    @Test
    void tls13OnlySuiteWithTls12OnlyProtocolsFailsFast() {
        TlsConfigurationException error = assertThrows(TlsConfigurationException.class,
                () -> TlsCipherSuitePolicy.resolve(
                        List.of(TlsProtocols.TLS_1_2),
                        List.of("TLS_AES_128_GCM_SHA256"), capabilities));
        assertTrue(error.getMessage().contains("TLS 1.3-only"));
    }

    @Test
    void tls12SuiteWithTls13OnlyProtocolsFailsFast() {
        TlsConfigurationException error = assertThrows(TlsConfigurationException.class,
                () -> TlsCipherSuitePolicy.resolve(
                        List.of(TlsProtocols.TLS_1_3),
                        List.of("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"), capabilities));
        assertTrue(error.getMessage().contains("TLS 1.2"));
    }
}
