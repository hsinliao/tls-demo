package com.example.tls.integration;

import com.example.tls.client.TlsClient;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;
import com.example.tls.connection.TlsConnection;
import com.example.tls.observability.HandshakeInfo;
import com.example.tls.server.TlsConnectionHandler;
import com.example.tls.server.TlsServer;
import com.example.tls.testing.TestCertificates;
import com.example.tls.testing.TestTls;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real handshake matrix:
 * protocol (TLS 1.2 / TLS 1.3) × client authentication (NONE / WANT / NEED).
 */
class TlsHandshakeMatrixTest {

    private static TestCertificates certs;

    private final TlsConnectionHandler reportingEcho = connection -> {
        com.example.tls.connection.LineTlsConnection lines = TestTls.line(connection);
        HandshakeInfo info = lines.handshakeInfo();
        lines.sendLine("server-auth=" + info.peerCertificatesPresent()
                + " protocol=" + info.protocol()
                + " cipher=" + info.cipherSuite());
        Optional<String> line;
        while ((line = lines.receiveLine()).isPresent()) {
            lines.sendLine("echo:" + line.get());
        }
    };

    @BeforeAll
    static void setUp() {
        certs = TestCertificates.instance();
    }

    @Test
    void tls12WithNone() throws Exception {
        assertMatrix("tls12-none", List.of(TlsProtocols.TLS_1_2), ClientAuthMode.NONE,
                false, false, false);
    }

    @Test
    void tls12WithWantAndClientCertificate() throws Exception {
        assertMatrix("tls12-want-cert", List.of(TlsProtocols.TLS_1_2), ClientAuthMode.WANT,
                true, false, true);
    }

    @Test
    void tls12WithWantWithoutClientCertificate() throws Exception {
        assertMatrix("tls12-want-nocert", List.of(TlsProtocols.TLS_1_2), ClientAuthMode.WANT,
                false, false, false);
    }

    @Test
    void tls12WithNeed() throws Exception {
        assertMatrix("tls12-need", List.of(TlsProtocols.TLS_1_2), ClientAuthMode.NEED,
                true, false, true);
    }

    @Test
    void tls13WithNone() throws Exception {
        assertMatrix("tls13-none", List.of(TlsProtocols.TLS_1_3), ClientAuthMode.NONE,
                false, true, false);
    }

    @Test
    void tls13WithWantAndClientCertificate() throws Exception {
        assertMatrix("tls13-want-cert", List.of(TlsProtocols.TLS_1_3), ClientAuthMode.WANT,
                true, true, true);
    }

    @Test
    void tls13WithWantWithoutClientCertificate() throws Exception {
        assertMatrix("tls13-want-nocert", List.of(TlsProtocols.TLS_1_3), ClientAuthMode.WANT,
                false, true, false);
    }

    @Test
    void tls13WithNeed() throws Exception {
        assertMatrix("tls13-need", List.of(TlsProtocols.TLS_1_3), ClientAuthMode.NEED,
                true, true, true);
    }

    @Test
    void noneWithClientCertificateDoesNotRequireIt() throws Exception {
        assertMatrix("tls13-none-with-client-cert", List.of(TlsProtocols.TLS_1_3),
                ClientAuthMode.NONE, true, true, false);
    }

    private void assertMatrix(String name, List<String> protocols, ClientAuthMode mode,
                              boolean clientHasCertificate, boolean tls13,
                              boolean expectedServerAuth) throws Exception {
        Path key = certs.serverP12();
        Path trust = mode == ClientAuthMode.NONE ? null : certs.serverTrustStore();
        TlsConfig serverConfig = TestTls.serverConfig(name + "-server", protocols, mode,
                List.of(), key, trust);
        TlsConfig clientConfig = TestTls.clientConfig(name + "-client", protocols, List.of(),
                clientHasCertificate ? certs.clientP12() : null, certs.clientTrustStore());

        try (TlsServer server = TlsServer.builder()
                .config(serverConfig)
                .passwords(TestTls.passwords())
                .handler(reportingEcho)
                .build()) {
            server.start(0);
            try (TlsClient client = TlsClient.builder()
                    .config(clientConfig)
                    .passwords(TestTls.passwords())
                    .build();
                 TlsConnection connection = TestTls.connect(client, server)) {

                assertEquals(tls13 ? TlsProtocols.TLS_1_3 : TlsProtocols.TLS_1_2,
                        connection.handshakeInfo().protocol());
                assertFalse(connection.handshakeInfo().cipherSuite().isBlank());

                String banner = TestTls.exchange(connection, "matrix-" + name);
                boolean serverObservedClientAuth =
                        Boolean.parseBoolean(banner.substring("server-auth=".length(), banner.indexOf(' ')));
                assertEquals(expectedServerAuth, serverObservedClientAuth, banner);
                assertTrue(banner.contains("protocol=" + (tls13 ? "TLSv1.3" : "TLSv1.2")), banner);
            }
        }
    }
}
