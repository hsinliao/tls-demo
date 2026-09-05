package com.example.tls.integration;

import com.example.tls.client.TlsClient;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;
import com.example.tls.connection.TlsConnection;
import com.example.tls.context.JsseCapabilities;
import com.example.tls.server.TlsConnectionHandler;
import com.example.tls.server.TlsServer;
import com.example.tls.testing.TestCertificates;
import com.example.tls.testing.TestTls;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies negotiated cipher suites under the default and strict-whitelist
 * policies with real JSSE handshakes.
 */
class TlsCipherSuiteIntegrationTest {

    private static TestCertificates certs;

    private final TlsConnectionHandler echo = connection -> {
        com.example.tls.connection.LineTlsConnection lines = TestTls.line(connection);
        lines.sendLine("connected");
        java.util.Optional<String> line;
        while ((line = lines.receiveLine()).isPresent()) {
            lines.sendLine("echo:" + line.get());
        }
    };

    @BeforeAll
    static void setUp() {
        certs = TestCertificates.instance();
    }

    @Test
    void defaultPolicyNegotiatesOneOfTheJdkEnabledSuites() throws Exception {
        List<String> protocols = List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2);
        TlsConfig serverConfig = TestTls.serverConfig(
                "default-cipher-server", protocols, ClientAuthMode.NONE,
                List.of(), certs.serverP12(), null);
        TlsConfig clientConfig = TestTls.clientConfig(
                "default-cipher-client", protocols, List.of(), null, certs.clientTrustStore());

        String negotiated = exchangeAndGetCipher(serverConfig, clientConfig);
        assertTrue(JsseCapabilities.probe().defaultEnabledCipherSuites().contains(negotiated),
                "negotiated suite must come from the JDK default-enabled set");
    }

    @Test
    void explicitTls13WhitelistNegotiatesOnlyTheConfiguredSuite() throws Exception {
        List<String> protocols = List.of(TlsProtocols.TLS_1_3);
        List<String> whitelist = List.of("TLS_AES_256_GCM_SHA384");
        TlsConfig serverConfig = TestTls.serverConfig(
                "explicit-tls13-server", protocols, ClientAuthMode.NONE,
                whitelist, certs.serverP12(), null);
        TlsConfig clientConfig = TestTls.clientConfig(
                "explicit-tls13-client", protocols, whitelist, null, certs.clientTrustStore());

        assertEquals("TLS_AES_256_GCM_SHA384", exchangeAndGetCipher(serverConfig, clientConfig));
    }

    @Test
    void explicitTls12WhitelistNegotiatesOnlyTheConfiguredSuite() throws Exception {
        List<String> protocols = List.of(TlsProtocols.TLS_1_2);
        List<String> whitelist = List.of("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        TlsConfig serverConfig = TestTls.serverConfig(
                "explicit-tls12-server", protocols, ClientAuthMode.NONE,
                whitelist, certs.serverP12(), null);
        TlsConfig clientConfig = TestTls.clientConfig(
                "explicit-tls12-client", protocols, whitelist, null, certs.clientTrustStore());

        assertEquals("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                exchangeAndGetCipher(serverConfig, clientConfig));
    }

    private String exchangeAndGetCipher(TlsConfig serverConfig, TlsConfig clientConfig) throws Exception {
        try (TlsServer server = TlsServer.builder()
                .config(serverConfig)
                .passwords(TestTls.passwords())
                .handler(echo)
                .build()) {
            server.start(0);
            try (TlsClient client = TlsClient.builder()
                    .config(clientConfig)
                    .passwords(TestTls.passwords())
                    .build();
                 TlsConnection connection = TestTls.connect(client, server)) {
                TestTls.exchange(connection, "cipher-check");
                return connection.handshakeInfo().cipherSuite();
            }
        }
    }
}
