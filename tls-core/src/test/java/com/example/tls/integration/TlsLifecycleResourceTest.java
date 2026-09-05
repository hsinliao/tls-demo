package com.example.tls.integration;

import com.example.tls.client.TlsClient;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;
import com.example.tls.connection.TlsConnection;
import com.example.tls.exception.TlsException;
import com.example.tls.server.TlsServer;
import com.example.tls.server.TlsServerOptions;
import com.example.tls.testing.TestCertificates;
import com.example.tls.testing.TestTls;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that stop()/close() release the listener, worker threads, tracked
 * sockets, and the bound port (including close-without-start).
 */
class TlsLifecycleResourceTest {

    private static final String SERVER_NAME = "demo-lifecycle";

    private static TestCertificates certs;

    @BeforeAll
    static void setUp() {
        certs = TestCertificates.instance();
    }

    @Test
    void stopReleasesListenerThreadsSocketAndPortEvenWithOpenConnection() throws Exception {
        TlsConfig serverConfig = TestTls.serverConfig(
                SERVER_NAME, List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
                ClientAuthMode.NONE, List.of(), certs.serverP12(), null);
        TlsServerOptions options = new TlsServerOptions(
                10, 1, 4, Duration.ofMillis(500));

        try (TlsServer server = TlsServer.builder()
                .config(serverConfig)
                .passwords(TestTls.passwords())
                .handler(connection -> {
                    com.example.tls.connection.LineTlsConnection lines = TestTls.line(connection);
                    lines.sendLine("connected");
                    Optional<String> line;
                    while ((line = lines.receiveLine()).isPresent()) {
                        lines.sendLine("echo:" + line.get());
                    }
                })
                .options(options)
                .build();
             TlsClient client = TlsClient.builder()
                     .config(TestTls.clientConfig("lifecycle-client",
                             List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2),
                             List.of(), null, certs.clientTrustStore()))
                     .passwords(TestTls.passwords())
                     .build()) {
            server.start(0);
            int port = server.localPort();
            assertTrue(port > 0);

            TlsConnection connection = TestTls.connect(client, server);
            com.example.tls.connection.LineTlsConnection lines = TestTls.line(connection);
            assertEquals("connected", lines.receiveLine().orElseThrow());
            // 内置指标无需额外注册 observer，默认记录成功握手。
            assertTrue(server.metrics().handshakeSuccesses() >= 1);

            // 连接仍打开时停止：宽限期 500ms 后应强制关闭所有在途资源。
            server.stop();

            assertFalse(server.isRunning());
            assertEquals(-1, server.localPort());
            try {
                Optional<String> response = lines.receiveLine();
                assertTrue(response.isEmpty(), "server must close the tracked connection during stop");
            } catch (TlsException expected) {
                // 对端关闭/重置同样证明服务端已释放 socket。
            }
            connection.close();

            awaitNoTlsServerThreads();
            assertPortCanBeRebound(port);

            // stop() 幂等：再次 close 不抛异常。
            server.close();
        }
    }

    @Test
    void closeWithoutStartStillShutsDownWorkerPool() throws Exception {
        TlsConfig serverConfig = TestTls.serverConfig(
                "never-started", List.of(TlsProtocols.TLS_1_3),
                ClientAuthMode.NONE, List.of(), certs.serverP12(), null);
        try (TlsServer server = TlsServer.builder()
                .config(serverConfig)
                .passwords(TestTls.passwords())
                .handler(connection -> {
                    TestTls.line(connection).receiveLine();
                })
                .build()) {
            server.close(); // 不应抛异常，也不应残留线程
        }
        awaitNoTlsServerThreads();
    }

    private static void assertPortCanBeRebound(int port) throws Exception {
        try (ServerSocket rebind = new ServerSocket()) {
            rebind.setReuseAddress(true);
            rebind.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        }
    }

    private static void awaitNoTlsServerThreads() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (hasTlsServerThread() && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        assertFalse(hasTlsServerThread(), "TLS server threads must terminate after stop()");
    }

    private static boolean hasTlsServerThread() {
        return Thread.getAllStackTraces().keySet().stream()
                .anyMatch(thread -> thread.getName().startsWith("tls-server-"));
    }
}
