package com.example.tls.demo.config;

import com.example.tls.config.ClientAuthentication;
import com.example.tls.config.StoreConfig;
import com.example.tls.config.TlsConfig;
import com.example.tls.config.TlsProtocols;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Demo-only loader that maps a flat {@code .properties} file onto the immutable
 * core {@link TlsConfig}. This loader is deliberately not part of the core so
 * real applications can bind their own config sources.
 *
 * <p>Passwords are never stored in the properties file; only symbolic secret
 * names are configured (defaulting to {@code TLS_KEYSTORE_PASSWORD} and
 * {@code TLS_TRUSTSTORE_PASSWORD}).
 */
public final class TlsPropertiesLoader {

    private TlsPropertiesLoader() {
    }

    public static LoadedConfig load(Path propertiesFile) {
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(propertiesFile)) {
            properties.load(reader);
        } catch (IOException e) {
            throw new IllegalArgumentException(
                    "Unable to read properties file " + propertiesFile.toAbsolutePath(), e);
        }
        return new LoadedConfig(buildTlsConfig(properties), demo(properties));
    }

    /** Parsed demo-only properties plus the core TLS configuration. */
    public record LoadedConfig(TlsConfig tlsConfig, // 核心 TLS 配置
                               DemoSettings demo) { // demo 专属的 peer/消息设置
    }

    /** Peer/port defaults used by the demo client, independent from the core API. */
    public record DemoSettings(String peerHost, // 客户端连接/校验的主机名
                               int peerPort,    // 客户端端口
                               String message) { // 默认发送的应用消息
    }

    private static TlsConfig buildTlsConfig(Properties properties) {
        TlsConfig.Builder builder = TlsConfig.builder()
                .name(properties.getProperty("tls.name", "tls"))
                .protocols(parseList(properties.getProperty("tls.protocols",
                        String.join(",", TlsProtocols.DEFAULT))))
                .cipherSuites(parseList(properties.getProperty("tls.cipherSuites", "")))
                .clientAuthentication(ClientAuthentication.of(
                        com.example.tls.config.ClientAuthMode.parse(
                                properties.getProperty("tls.clientAuthentication.mode", "NONE"))))
                .keyStore(parseStore(properties, "tls.keyStore",
                        "TLS_KEYSTORE_PASSWORD"))
                .trustStore(parseStore(properties, "tls.trustStore",
                        "TLS_TRUSTSTORE_PASSWORD"))
                .hostnameVerificationEnabled(parseBoolean(
                        properties.getProperty("tls.hostnameVerification.enabled", "true")))
                .connectTimeoutMillis(parseMillis(properties,
                        "tls.connectTimeoutMillis", 5_000))
                .handshakeTimeoutMillis(parseMillis(properties,
                        "tls.handshakeTimeoutMillis", 10_000))
                .socketTimeoutMillis(parseMillis(properties,
                        "tls.socketTimeoutMillis", 30_000))
                .applicationProtocols(parseList(properties.getProperty("tls.applicationProtocols", "")));
        return builder.build();
    }

    private static StoreConfig parseStore(Properties properties, String prefix, String defaultPasswordKey) {
        // store 段不解析“真实密码”，只解析密码的符号名（默认 TLS_KEYSTORE/TRUSTSTORE_PASSWORD）；
        // 真实值由 PasswordProvider 在运行时注入，保证配置文件可安全入库。
        String type = properties.getProperty(prefix + ".type", StoreConfig.DEFAULT_TYPE);
        String passwordKey = properties.getProperty(prefix + ".passwordKey", defaultPasswordKey);
        String keyPasswordKey = blankToNull(properties.getProperty(prefix + ".keyPasswordKey", ""));
        String alias = blankToNull(properties.getProperty(prefix + ".alias", ""));
        String providerName = blankToNull(properties.getProperty(prefix + ".providerName", ""));
        if (providerName != null) {
            // Provider-backed 形态（例如 HSM）：不再要求 path。
            return StoreConfig.provider(type, providerName, passwordKey);
        }
        String path = properties.getProperty(prefix + ".path", "").trim();
        if (path.isEmpty()) {
            return null;
        }
        return StoreConfig.file(type, Path.of(path), passwordKey, keyPasswordKey, alias);
    }

    private static DemoSettings demo(Properties properties) {
        String host = properties.getProperty("demo.peer.host", "localhost");
        int port = parseInt(properties.getProperty("demo.peer.port", "8443"), "demo.peer.port");
        String message = properties.getProperty("demo.message", "Hello from TLS client");
        return new DemoSettings(host, port, message);
    }

    private static long parseMillis(Properties properties, String key, long defaultValue) {
        String value = properties.getProperty(key);
        return value == null || value.isBlank() ? defaultValue : Long.parseLong(value.trim());
    }

    private static int parseInt(String value, String key) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("'" + key + "' must be an integer, got '" + value + "'", e);
        }
    }

    private static boolean parseBoolean(String value) {
        if ("true".equalsIgnoreCase(value.trim()) || "false".equalsIgnoreCase(value.trim())) {
            return Boolean.parseBoolean(value.trim());
        }
        throw new IllegalArgumentException("Expected boolean true/false, got '" + value + "'");
    }

    private static List<String> parseList(String value) {
        List<String> result = new ArrayList<>();
        if (value == null) {
            return result;
        }
        for (String item : value.split(",")) {
            String trimmed = item.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return List.copyOf(result);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
