package com.example.tls.integration;

import com.example.tls.client.TlsClient;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;
import com.example.tls.connection.TlsConnection;
import com.example.tls.exception.TlsConnectionException;
import com.example.tls.exception.TlsHandshakeException;
import com.example.tls.server.TlsConnectionHandler;
import com.example.tls.server.TlsServer;
import com.example.tls.testing.TestCertificates;
import com.example.tls.testing.TestTls;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Negative mTLS behavior required by the acceptance criteria.
 */
class TlsNegativeAuthTest {

    private static TestCertificates certs;

    private final TlsConnectionHandler echo = connection -> {
        com.example.tls.connection.LineTlsConnection lines = TestTls.line(connection);
        lines.sendLine("connected server-auth=" + lines.handshakeInfo().peerCertificatesPresent());
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
    void needWithoutClientCertificateFailsHandshake() throws Exception {
        assertNeedFails(null);
    }

    @Test
    void needWithClientCertificateFromUntrustedCaFailsHandshake() throws Exception {
        assertNeedFails(certs.untrustedClientP12());
    }

    private void assertNeedFails(Path clientKeyStore) throws Exception {
        TlsConfig serverConfig = TestTls.serverConfig(
                "need-negative-server", List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
                ClientAuthMode.NEED, List.of(), certs.serverP12(), certs.serverTrustStore());
        TlsConfig clientConfig = TestTls.clientConfig(
                "need-negative-client", List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
                List.of(), clientKeyStore, certs.clientTrustStore());

        try (TlsServer server = TlsServer.builder()
                .config(serverConfig)
                .passwords(TestTls.passwords())
                .handler(echo)
                .build()) {
            server.start(0);
            try (TlsClient client = TlsClient.builder()
                    .config(clientConfig)
                    .passwords(TestTls.passwords())
                    .build()) {
                boolean failed = false;
                try {
                    try (TlsConnection connection = TestTls.connect(client, server)) {
                        com.example.tls.connection.LineTlsConnection lines = TestTls.line(connection);
                        lines.sendLine("probe");
                        failed = lines.receiveLine().isEmpty();
                    }
                } catch (TlsHandshakeException | TlsConnectionException e) {
                    failed = true;
                }
                assertTrue(failed, "mTLS NEED must reject a client without an acceptable certificate");
            }
        }
    }

    @Test
    void wantWithoutClientCertificateIsAllowed() throws Exception {
        TlsConfig serverConfig = TestTls.serverConfig(
                "want-optional", List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
                ClientAuthMode.WANT, List.of(), certs.serverP12(), certs.serverTrustStore());
        TlsConfig clientConfig = TestTls.clientConfig(
                "want-optional-client", List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
                List.of(), null, certs.clientTrustStore());

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
                com.example.tls.connection.LineTlsConnection lines = TestTls.line(connection);
                lines.sendLine("hi");
                String banner = lines.receiveLine().orElseThrow();
                org.junit.jupiter.api.Assertions.assertTrue(banner.contains("server-auth=false"), banner);
                org.junit.jupiter.api.Assertions.assertEquals("echo:hi",
                        lines.receiveLine().orElseThrow());
            }
        }
    }
}
