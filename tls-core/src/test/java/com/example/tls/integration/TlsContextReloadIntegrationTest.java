package com.example.tls.integration;

import com.example.tls.client.TlsClient;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.StoreConfig;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;
import com.example.tls.connection.TlsConnection;
import com.example.tls.context.TlsContext;
import com.example.tls.exception.TlsConfigurationException;
import com.example.tls.server.TlsConnectionHandler;
import com.example.tls.server.TlsServer;
import com.example.tls.testing.TestCertificates;
import com.example.tls.testing.TestTls;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Certificate rotation / SSLContext reload semantics:
 * existing connections keep their session, new connections use the reloaded
 * context, and a failed reload keeps the old context current.
 */
class TlsContextReloadIntegrationTest {

    private static TestCertificates certs;

    @TempDir
    Path tempDir;

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
    void reloadKeepsExistingConnectionAndServesNewConnectionsFromNewContext() throws Exception {
        List<String> protocols = List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2);
        // 每个测试使用独立的临时 keystore 副本，避免污染共享测试夹具。
        Path serverIdentity = tempDir.resolve("server.p12");
        Path rotatedIdentity = tempDir.resolve("server-rotated.p12");
        Files.copy(certs.serverP12(), serverIdentity);
        Files.copy(certs.rotatedServerP12(), rotatedIdentity);
        TlsConfig initial = TestTls.serverConfig(
                "rotation-server", protocols, ClientAuthMode.NONE,
                List.of(), serverIdentity, null);
        AtomicReference<TlsConfig> configRef = new AtomicReference<>(initial);

        try (TlsServer server = TlsServer.builder()
                .configSupplier(configRef::get)
                .passwords(TestTls.passwords())
                .handler(echo)
                .build();
             TlsClient client = TlsClient.builder()
                     .config(TestTls.clientConfig("rotation-client", protocols, List.of(),
                             null, certs.clientTrustStore()))
                     .passwords(TestTls.passwords())
                     .build()) {
            server.start(0);

            TlsContext oldContext = server.contextProvider().current();
            try (TlsConnection connection = TestTls.connect(client, server)) {
                com.example.tls.connection.LineTlsConnection lines = TestTls.line(connection);
                lines.sendLine("before-reload");
                assertEquals("connected", lines.receiveLine().orElseThrow());
                assertEquals("echo:before-reload", lines.receiveLine().orElseThrow());

                // Replace the key store on disk and publish the rotated config.
                Files.copy(rotatedIdentity, serverIdentity, StandardCopyOption.REPLACE_EXISTING);
                configRef.set(initial.toBuilder().name("rotation-server-rotated").build());
                TlsContext newContext = server.reloadTlsContext();

                assertNotSame(oldContext, newContext);
                assertSame(newContext, server.contextProvider().current());

                // The pre-existing TLS session/connection survives the reload.
                lines.sendLine("after-reload");
                assertEquals("echo:after-reload", lines.receiveLine().orElseThrow());
            }

            // New connections are served by the rotated listener/context.
            try (TlsConnection fresh = TestTls.connect(client, server)) {
                com.example.tls.connection.LineTlsConnection freshLines = TestTls.line(fresh);
                assertEquals("connected", freshLines.receiveLine().orElseThrow());
                freshLines.sendLine("fresh-connection");
                assertEquals("echo:fresh-connection", freshLines.receiveLine().orElseThrow());
            }

            // A failed reload must not replace the working context.
            TlsContext beforeFailure = server.contextProvider().current();
            TlsConfig broken = TestTls.serverConfig(
                    "rotation-broken", protocols, ClientAuthMode.NONE,
                    List.of(), Path.of("does-not-exist.p12"), null);
            configRef.set(broken);
            assertThrows(TlsConfigurationException.class, server::reloadTlsContext);
            assertSame(beforeFailure, server.contextProvider().current());
            assertEquals("rotation-server-rotated", server.contextProvider().current().config().name());
        }
    }
}
