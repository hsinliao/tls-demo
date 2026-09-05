package com.example.tls.demo;

import com.example.tls.client.TlsClient;
import com.example.tls.config.TlsConfig;
import com.example.tls.connection.TlsConnection;
import com.example.tls.connection.LineTlsConnection;
import com.example.tls.context.TlsContext;
import com.example.tls.demo.config.TlsPropertiesLoader;
import com.example.tls.demo.config.LocalScriptPasswordProvider;
import com.example.tls.demo.server.DemoEchoHandler;
import com.example.tls.observability.HandshakeInfo;
import com.example.tls.observability.LoggingTlsHandshakeObserver;
import com.example.tls.security.CompositePasswordProvider;
import com.example.tls.security.EnvironmentPasswordProvider;
import com.example.tls.security.PasswordProvider;
import com.example.tls.security.SystemPropertyPasswordProvider;
import com.example.tls.server.TlsServer;

import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;

/**
 * Executable demo entry point.
 *
 * <pre>
 * java -jar tls-demo-1.0.0.jar server --config path/to/server.properties [--host 127.0.0.1] [--port 8443]
 * java -jar tls-demo-1.0.0.jar client --config path/to/client.properties [--host localhost] [--port 8443] [--message hi]
 * </pre>
 */
public final class TlsDemo {

    private TlsDemo() {
    }

    public static void main(String[] args) {
        try {
            if (args.length == 0) {
                printUsage();
                System.exit(2);
            }
            String command = args[0];
            String[] rest = new String[args.length - 1];
            System.arraycopy(args, 1, rest, 0, rest.length);
            switch (command) {
                case "server" -> runServer(rest);
                case "client" -> runClient(rest);
                case "--help", "-h", "help" -> printUsage();
                default -> {
                    System.err.println("Unknown command: " + command);
                    printUsage();
                    System.exit(2);
                }
            }
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    private static void runServer(String[] args) throws Exception {
        ParsedArguments parsed = ParsedArguments.parse(args, "server");
        TlsPropertiesLoader.LoadedConfig loaded =
                TlsPropertiesLoader.load(Path.of(parsed.required("config")));
        TlsConfig config = loaded.tlsConfig();
        String host = parsed.optional("host", "127.0.0.1");
        int port = parsed.intOptional("port", 8443);

        TlsServer server = TlsServer.builder()
                .config(config)
                .passwords(demoPasswords(com.example.tls.config.EndpointRole.SERVER))
                .handler(new DemoEchoHandler())
                .observer(new LoggingTlsHandshakeObserver())
                .build();

        server.start(host, port);
        printEffectiveConfiguration(server.contextProvider().current(), "server");

        CountDownLatch shutdown = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            // Ctrl+C / SIGTERM 时优雅关闭：先停 accept，再等 worker 池结束。
            server.close();
            shutdown.countDown();
        }, "tls-demo-shutdown"));
        System.out.println("Server is running. Press Ctrl+C to stop.");
        shutdown.await();
    }

    private static void runClient(String[] args) throws Exception {
        ParsedArguments parsed = ParsedArguments.parse(args, "client");
        TlsPropertiesLoader.LoadedConfig loaded =
                TlsPropertiesLoader.load(Path.of(parsed.required("config")));
        TlsConfig config = loaded.tlsConfig();
        String host = parsed.optional("host", loaded.demo().peerHost());
        int port = parsed.intOptional("port", loaded.demo().peerPort());
        String message = parsed.optional("message", loaded.demo().message());

        try (TlsClient client = TlsClient.builder()
                .config(config)
                .passwords(demoPasswords(com.example.tls.config.EndpointRole.CLIENT))
                .observer(new LoggingTlsHandshakeObserver())
                .build();
             TlsConnection connection = client.connect(host, port);
             LineTlsConnection lines = LineTlsConnection.wrap(connection)) {

            HandshakeInfo info = lines.handshakeInfo();
            System.out.println();
            System.out.println("TLS connection established");
            System.out.println();
            System.out.println("Protocol: " + info.protocol());
            System.out.println("Cipher Suite: " + info.cipherSuite());
            System.out.println("Client certificate presented: " + info.localCertificatesPresent());
            System.out.println();
            System.out.println("Peer:");
            System.out.println("  Subject: " + safe(info.peerSubjectDn()));
            System.out.println("  Issuer:  " + safe(info.peerIssuerDn()));
            System.out.println();
            System.out.println("Handshake: SUCCESS");
            System.out.println();

            lines.sendLine(message);
            Optional<String> banner = lines.receiveLine();
            banner.ifPresent(System.out::println);
            Optional<String> echo = lines.receiveLine();
            echo.ifPresent(System.out::println);
        }
    }

    /**
     * 优先级：环境变量 > JVM 系统属性 > Demo 脚本生成的本地密码文件。
     * 本地文件回退只服务于 IDE 直接运行；生产应只用前两者背后的 Secret 管理机制。
     */
    private static PasswordProvider demoPasswords(com.example.tls.config.EndpointRole role) {
        return CompositePasswordProvider.of(
                new EnvironmentPasswordProvider(),
                new SystemPropertyPasswordProvider(),
                new LocalScriptPasswordProvider(role));
    }

    private static void printEffectiveConfiguration(TlsContext context, String role) {
        // 启动自检输出。刻意不打印密码、私钥或秘密的明文值。
        TlsConfig config = context.config();
        System.out.println("=== Effective TLS configuration [" + config.name() + "] ===");
        System.out.println("Role: " + role);
        System.out.println("Enabled protocols: " + context.effectiveProtocols());
        System.out.println("Client authentication mode: " + config.clientAuthentication().mode());
        System.out.println("Cipher suites: " + (context.cipherSuitesExplicitlyConfigured()
                ? "explicit whitelist " + context.effectiveCipherSuites()
                : "JDK JSSE defaults (" + context.effectiveCipherSuites().size() + " suites enabled by the JVM)"));
        System.out.println("Key store: " + describeStore(config.keyStore()));
        System.out.println("Trust store: " + describeStore(config.trustStore()));
        System.out.println("Hostname verification: " + config.hostnameVerificationEnabled());
        System.out.println("Timeouts (ms): connect=" + config.connectTimeout().toMillis()
                + " handshake=" + config.handshakeTimeout().toMillis()
                + " socket=" + config.socketTimeout().toMillis());
        System.out.println("TLS context id: " + context.id() + " (created " + context.createdAt() + ")");
        System.out.println("=======================================");
    }

    private static String describeStore(com.example.tls.config.StoreConfig store) {
        if (store == null) {
            return "not configured";
        }
        String location = store.isProviderBased()
                ? "provider=" + store.providerName()
                : "path=" + store.path().toAbsolutePath();
        return "type=" + store.type() + " " + location
                + " alias=" + (store.alias() == null ? "(auto)" : store.alias());
    }

    private static String safe(String value) {
        return value == null ? "(none)" : value;
    }

    private static void printUsage() {
        System.out.println("""
                Usage:
                  java -jar tls-demo-1.0.0.jar server --config <file> [--host 127.0.0.1] [--port 8443]
                  java -jar tls-demo-1.0.0.jar client --config <file> [--host localhost] [--port 8443] [--message <text>]
                """);
    }

    /** Minimal key/value argument parser for the demo CLI. */
    private record ParsedArguments(java.util.Map<String, String> values) { // --key value 映射

        static ParsedArguments parse(String[] args, String command) {
            java.util.Map<String, String> values = new java.util.HashMap<>();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if (!arg.startsWith("--")) {
                    throw new IllegalArgumentException(
                            "Unexpected argument '" + arg + "' for command '" + command + "'");
                }
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("Missing value for " + arg);
                }
                values.put(arg.substring(2), args[++i]);
            }
            return new ParsedArguments(values);
        }

        String required(String key) {
            String value = values.get(key);
            if (value == null) {
                throw new IllegalArgumentException("Missing required option --" + key);
            }
            return value;
        }

        String optional(String key, String defaultValue) {
            return values.getOrDefault(key, defaultValue);
        }

        int intOptional(String key, int defaultValue) {
            String value = values.get(key);
            if (value == null) {
                return defaultValue;
            }
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("--" + key + " must be an integer: '" + value + "'", e);
            }
        }
    }
}
