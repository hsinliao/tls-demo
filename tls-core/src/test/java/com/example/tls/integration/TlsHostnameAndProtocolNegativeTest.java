package com.example.tls.integration;

import com.example.tls.client.TlsClient;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;
import com.example.tls.exception.TlsHandshakeException;
import com.example.tls.server.TlsConnectionHandler;
import com.example.tls.server.TlsServer;
import com.example.tls.testing.TestCertificates;
import com.example.tls.testing.TestTls;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Hostname verification and no-downgrade negative tests.
 */
class TlsHostnameAndProtocolNegativeTest {

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
    void hostnameMismatchFailsEvenThoughCertificateChainIsTrusted() throws Exception {
        TlsConfig serverConfig = TestTls.serverConfig(
                "wrong-host-server", List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
                ClientAuthMode.NONE, List.of(), certs.wrongHostServerP12(), null);
        TlsConfig clientConfig = TestTls.clientConfig(
                "wrong-host-client", List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
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
                    .build()) {
                InetSocketAddress address =
                        new InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.localPort());
                TlsHandshakeException error = assertThrows(TlsHandshakeException.class,
                        () -> client.connectTo("localhost", address).close());
                assertTrue(error.getMessage().contains("localhost"));
            }
        }
    }

    @Test
    void noAutomaticDowngradeWhenProtocolSetsDoNotOverlap() throws Exception {
        TlsConfig serverConfig = TestTls.serverConfig(
                "only-tls13-server", List.of(TlsProtocols.TLS_1_3),
                ClientAuthMode.NONE, List.of(), certs.serverP12(), null);
        TlsConfig clientConfig = TestTls.clientConfig(
                "only-tls12-client", List.of(TlsProtocols.TLS_1_2),
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
                    .build()) {
                TlsHandshakeException error = assertThrows(TlsHandshakeException.class,
                        () -> TestTls.connect(client, server).close());
                assertTrue(error.getMessage().toLowerCase().contains("handshake")
                        || error.getMessage().toLowerCase().contains("protocol"));
            }
        }
    }
}
