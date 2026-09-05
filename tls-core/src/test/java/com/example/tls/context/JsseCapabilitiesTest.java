package com.example.tls.context;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsseCapabilitiesTest {

    @Test
    void defaultJdk17ProviderSupportsTls12AndTls13() {
        JsseCapabilities capabilities = JsseCapabilities.probe();
        assertTrue(capabilities.supportedProtocols().contains("TLSv1.2"));
        assertTrue(capabilities.supportedProtocols().contains("TLSv1.3"));
        assertFalse(capabilities.defaultEnabledCipherSuites().isEmpty());
        assertTrue(capabilities.defaultProtocols().contains("TLSv1.3"));
        assertTrue(capabilities.defaultProtocols().contains("TLSv1.2"));
    }
}
