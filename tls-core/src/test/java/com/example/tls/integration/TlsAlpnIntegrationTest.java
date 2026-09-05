package com.example.tls.integration;

import com.example.tls.client.TlsClient;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;
import com.example.tls.connection.TlsConnection;
import com.example.tls.server.TlsConnectionHandler;
import com.example.tls.server.TlsServer;
import com.example.tls.testing.TestCertificates;
import com.example.tls.testing.TestTls;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * ALPN is reserved but fully functional: both peers configure the same
 * application protocol and the negotiated value is observable.
 */
class TlsAlpnIntegrationTest {

    private static final String ALPN_PROTOCOL = "demo-tls/1";

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
    void alpnProtocolIsNegotiatedAndObserved() throws Exception {
        List<String> protocols = List.of(TlsProtocols.TLS_1_3);
        TlsConfig serverConfig = TestTls.serverConfig(
                "alpn-server", protocols, ClientAuthMode.NONE,
                List.of(), certs.serverP12(), null)
                .toBuilder()
                .applicationProtocols(List.of(ALPN_PROTOCOL))
                .build();
        TlsConfig clientConfig = TestTls.clientConfig(
                "alpn-client", protocols, List.of(), null, certs.clientTrustStore())
                .toBuilder()
                .applicationProtocols(List.of(ALPN_PROTOCOL))
                .build();

        try (TlsServer server = TlsServer.builder()
                .config(serverConfig)
                .passwords(TestTls.passwords())
                .handler(echo)
                .build();
             TlsClient client = TlsClient.builder()
                     .config(clientConfig)
                     .passwords(TestTls.passwords())
                     .build()) {
            server.start(0);
            try (TlsConnection connection = TestTls.connect(client, server)) {
                TestTls.exchange(connection, "alpn-check");
                assertEquals(ALPN_PROTOCOL, connection.handshakeInfo().applicationProtocol());
            }
        }
    }
}
