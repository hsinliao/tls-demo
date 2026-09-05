package com.example.tls.testing;

import com.example.tls.client.TlsClient;
import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.StoreConfig;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;
import com.example.tls.connection.LineTlsConnection;
import com.example.tls.connection.TlsConnection;
import com.example.tls.security.FixedPasswordProvider;
import com.example.tls.security.PasswordProvider;
import com.example.tls.server.TlsServer;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Shared builders/connectors used by the integration tests. */
public final class TestTls {

    private TestTls() {
    }

    public static PasswordProvider passwords() {
        Map<String, String> secrets = new HashMap<>();
        secrets.put("TLS_KEYSTORE_PASSWORD", new String(TestCertificates.PASSWORD));
        secrets.put("TLS_TRUSTSTORE_PASSWORD", new String(TestCertificates.PASSWORD));
        return FixedPasswordProvider.of(secrets);
    }

    public static StoreConfig keyStore(Path path) {
        return StoreConfig.of("PKCS12", path, "TLS_KEYSTORE_PASSWORD");
    }

    public static StoreConfig trustStore(Path path) {
        return StoreConfig.of("PKCS12", path, "TLS_TRUSTSTORE_PASSWORD");
    }

    public static TlsConfig serverConfig(String name, List<String> protocols, ClientAuthMode mode,
                                         List<String> cipherSuites, Path keyStore, Path trustStore) {
        return TlsConfig.builder()
                .name(name)
                .protocols(protocols)
                .cipherSuites(cipherSuites)
                .clientAuthentication(mode)
                .keyStore(keyStore == null ? null : keyStore(keyStore))
                .trustStore(trustStore == null ? null : trustStore(trustStore))
                .build();
    }

    public static TlsConfig clientConfig(String name, List<String> protocols, List<String> cipherSuites,
                                         Path keyStore, Path trustStore) {
        return TlsConfig.builder()
                .name(name)
                .protocols(protocols)
                .cipherSuites(cipherSuites)
                .clientAuthentication(ClientAuthMode.NONE)
                .keyStore(keyStore == null ? null : keyStore(keyStore))
                .trustStore(trustStore == null ? null : trustStore(trustStore))
                .build();
    }

    public static InetSocketAddress loopback(TlsServer server) {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort());
    }

    /** Connects using the identity "localhost" while TCP targets 127.0.0.1. */
    public static TlsConnection connect(TlsClient client, TlsServer server) {
        return client.connectTo("localhost", loopback(server));
    }

    /** Application-layer line adapter used by the demo protocol in tests. */
    public static LineTlsConnection line(TlsConnection connection) {
        return LineTlsConnection.wrap(connection);
    }

    /**
     * Sends one request and reads the server's handshake banner plus the echo
     * response. Returns the banner.
     */
    public static String exchange(TlsConnection connection, String request) throws Exception {
        LineTlsConnection lines = LineTlsConnection.wrap(connection);
        lines.sendLine(request);
        String banner = lines.receiveLine().orElseThrow(() ->
                new AssertionError("Expected server handshake banner, got EOF"));
        Optional<String> echo = lines.receiveLine();
        if (echo.isEmpty() || !echo.get().equals("echo:" + request)) {
            throw new AssertionError("Unexpected echo response: " + echo.orElse("EOF"));
        }
        return banner;
    }

    public static List<String> protocolsBoth() {
        return List.of(TlsProtocols.TLS_1_3, TlsProtocols.TLS_1_2);
    }
}
