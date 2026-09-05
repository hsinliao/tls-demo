package com.example.tls.testing;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Test-only certificate authority. Generates two roots, server/client
 * identities, rotated and wrong-host certificates, PKCS12 stores, and
 * truststores into {@code target/generated-test-certs} using the system
 * {@code openssl} (all certificate material is test data; nothing is committed).
 *
 * <p>Real TLS behavior still runs entirely on JDK JSSE; openssl is only used to
 * prepare fixtures, exactly like the demo certificate scripts.
 */
public final class TestCertificates {

    /** Test-only store password. Never used outside test fixtures. */
    public static final char[] PASSWORD = "changeit-test-only".toCharArray();

    private static volatile TestCertificates INSTANCE;

    private final Path root;

    private TestCertificates(Path root) {
        this.root = root;
    }

    public static TestCertificates instance() {
        TestCertificates local = INSTANCE;
        if (local == null) {
            synchronized (TestCertificates.class) {
                local = INSTANCE;
                if (local == null) {
                    Path root = Path.of("target", "generated-test-certs").toAbsolutePath().normalize();
                    local = new TestCertificates(root);
                    local.generate();
                    INSTANCE = local;
                }
            }
        }
        return INSTANCE;
    }

    public Path root() {
        return root;
    }

    public Path ca1Crt() {
        return root.resolve("ca1/ca.crt");
    }

    public Path ca2Crt() {
        return root.resolve("ca2/ca.crt");
    }

    public Path serverP12() {
        return root.resolve("server.p12");
    }

    public Path rotatedServerP12() {
        return root.resolve("server-rotated.p12");
    }

    public Path wrongHostServerP12() {
        return root.resolve("server-wronghost.p12");
    }

    public Path clientP12() {
        return root.resolve("client.p12");
    }

    public Path clientCrt() {
        return root.resolve("client/client.crt");
    }

    public Path untrustedClientP12() {
        return root.resolve("client-untrusted.p12");
    }

    public Path serverTrustStore() {
        return root.resolve("server-truststore.p12");
    }

    public Path serverTrustStoreTrustsCa2() {
        return root.resolve("server-truststore-ca2.p12");
    }

    public Path clientTrustStore() {
        return root.resolve("client-truststore.p12");
    }

    public Path expiredServerP12() {
        return root.resolve("server-expired.p12");
    }

    public Path expiredServerCrt() {
        return root.resolve("expired/expired.crt");
    }

    private void generate() {
        deleteRecursively(root);
        createDirectories(root);

        Path ca1 = root.resolve("ca1");
        Path ca2 = root.resolve("ca2");
        createDirectories(ca1);
        createDirectories(ca2);

        generateCa(ca1, "Demo Test CA 1");
        generateCa(ca2, "Demo Test CA 2");

        Path serverKey = leafIdentity(root.resolve("server"),
                "server", "CN=server", List.of("DNS.1=localhost", "DNS.2=server", "IP.1=127.0.0.1"),
                "serverAuth", ca1);
        Path serverCrt = root.resolve("server/server.crt");
        createP12(serverCrt, serverKey, ca1.resolve("ca.crt"), root.resolve("server.p12"), "server");

        Path rotatedKey = leafIdentity(root.resolve("server-rotated"),
                "server-rotated", "CN=server-rotated",
                List.of("DNS.1=localhost", "DNS.2=server", "IP.1=127.0.0.1"),
                "serverAuth", ca1);
        createP12(root.resolve("server-rotated/server-rotated.crt"), rotatedKey,
                ca1.resolve("ca.crt"), root.resolve("server-rotated.p12"), "server-rotated");

        Path wrongHostKey = leafIdentity(root.resolve("server-wronghost"),
                "server-wronghost", "CN=server-wronghost",
                List.of("DNS.1=wrong.host.example"), "serverAuth", ca1);
        createP12(root.resolve("server-wronghost/server-wronghost.crt"), wrongHostKey,
                ca1.resolve("ca.crt"), root.resolve("server-wronghost.p12"), "server-wronghost");

        Path clientKey = leafIdentity(root.resolve("client"),
                "client", "CN=client", List.of("DNS.1=client"), "clientAuth", ca1);
        createP12(root.resolve("client/client.crt"), clientKey,
                ca1.resolve("ca.crt"), root.resolve("client.p12"), "client");

        Path untrustedKey = leafIdentity(root.resolve("client-untrusted"),
                "client-untrusted", "CN=client-untrusted",
                List.of("DNS.1=client-untrusted"), "clientAuth", ca2);
        createP12(root.resolve("client-untrusted/client-untrusted.crt"), untrustedKey,
                ca2.resolve("ca.crt"), root.resolve("client-untrusted.p12"), "client-untrusted");

        createTrustStore(ca1.resolve("ca.crt"), serverTrustStore(), "demo-test-ca-1");
        createTrustStore(ca1.resolve("ca.crt"), clientTrustStore(), "demo-test-ca-1");
        createTrustStore(ca2.resolve("ca.crt"), serverTrustStoreTrustsCa2(), "demo-test-ca-2");

        generateExpiredIdentity(ca1);
    }

    private void generateExpiredIdentity(Path ca) {
        Path directory = root.resolve("expired");
        createDirectories(directory);
        Path key = directory.resolve("expired.key");
        Path csr = directory.resolve("expired.csr");
        Path crt = directory.resolve("expired.crt");

        write(directory.resolve("req.cnf"), """
                [req]
                distinguished_name = dn
                prompt = no

                [dn]
                CN = expired-server
                """);
        openssl("req", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes",
                "-config", directory.resolve("req.cnf").toString(),
                "-subj", "/CN=expired-server",
                "-keyout", key.toString(),
                "-out", csr.toString());

        write(directory.resolve("ext.cnf"), extensionConfig(
                List.of("DNS.1=localhost", "IP.1=127.0.0.1"), "serverAuth"));

        write(directory.resolve("ca.cnf"), """
                [ca]
                default_ca = demo_ca

                [demo_ca]
                database = %s/index.txt
                serial = %s/serial
                new_certs_dir = %s/newcerts
                certificate = %s
                private_key = %s
                default_md = sha256
                policy = policy_any
                default_days = 1

                [policy_any]
                commonName = supplied
                """.formatted(directory, directory, directory, ca.resolve("ca.crt"), ca.resolve("ca.key")));
        try {
            Files.writeString(directory.resolve("index.txt"), "", StandardCharsets.UTF_8);
            Files.writeString(directory.resolve("serial"), "1000\n", StandardCharsets.UTF_8);
            Files.createDirectories(directory.resolve("newcerts"));
        } catch (IOException e) {
            throw new IllegalStateException("Unable to initialize openssl ca database", e);
        }

        openssl("ca", "-batch",
                "-config", directory.resolve("ca.cnf").toString(),
                "-in", csr.toString(),
                "-out", crt.toString(),
                "-startdate", "20200101000000Z",
                "-enddate", "20210101000000Z",
                "-extfile", directory.resolve("ext.cnf").toString(),
                "-extensions", "leaf_ext");

        createP12(crt, key, ca.resolve("ca.crt"), expiredServerP12(), "expired-server");
    }

    private static void generateCa(Path directory, String commonName) {
        write(directory.resolve("ca-req.cnf"), """
                [req]
                distinguished_name = dn
                prompt = no
                x509_extensions = ca_ext

                [dn]
                CN = %s
                O = TLS Demo Tests

                [ca_ext]
                basicConstraints = critical,CA:TRUE,pathlen:1
                keyUsage = critical,keyCertSign,cRLSign
                subjectKeyIdentifier = hash
                """.formatted(commonName));
        openssl("req", "-x509", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes",
                "-config", directory.resolve("ca-req.cnf").toString(),
                "-keyout", directory.resolve("ca.key").toString(),
                "-out", directory.resolve("ca.crt").toString(),
                "-days", "3650");
    }

    /**
     * Generates a private key + CSR and signs it with {@code ca}.
     *
     * @return the path of the private key
     */
    private static Path leafIdentity(Path directory, String alias, String subjectDn,
                                     List<String> sanEntries, String eku, Path ca) {
        createDirectories(directory);
        Path key = directory.resolve(alias + ".key");
        Path csr = directory.resolve(alias + ".csr");
        Path crt = directory.resolve(alias + ".crt");

        write(directory.resolve("req.cnf"), """
                [req]
                distinguished_name = dn
                prompt = no

                [dn]
                CN = %s
                """.formatted(alias));
        write(directory.resolve("ext.cnf"), extensionConfig(sanEntries, eku));

        openssl("req", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes",
                "-config", directory.resolve("req.cnf").toString(),
                "-subj", subjectDn,
                "-keyout", key.toString(),
                "-out", csr.toString());
        openssl("x509", "-req",
                "-in", csr.toString(),
                "-CA", ca.resolve("ca.crt").toString(),
                "-CAkey", ca.resolve("ca.key").toString(),
                "-CAcreateserial",
                "-out", crt.toString(),
                "-days", "825",
                "-sha256",
                "-extfile", directory.resolve("ext.cnf").toString(),
                "-extensions", "leaf_ext");
        return key;
    }

    private static String extensionConfig(List<String> sanEntries, String eku) {
        StringBuilder config = new StringBuilder("""
                [leaf_ext]
                basicConstraints = critical,CA:FALSE
                keyUsage = critical,digitalSignature,keyEncipherment
                extendedKeyUsage = %s
                subjectAltName = @san
                authorityKeyIdentifier = keyid,issuer
                subjectKeyIdentifier = hash

                [san]
                """.formatted(eku));
        for (String entry : sanEntries) {
            config.append(entry).append('\n');
        }
        return config.toString();
    }

    private static void createP12(Path certificate, Path key, Path caCertificate,
                                  Path output, String alias) {
        openssl("pkcs12", "-export",
                "-name", alias,
                "-inkey", key.toString(),
                "-in", certificate.toString(),
                "-certfile", caCertificate.toString(),
                "-out", output.toString(),
                "-passout", "pass:" + new String(PASSWORD));
    }

    private static void createTrustStore(Path caCertificate, Path output, String alias) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            try (InputStream in = Files.newInputStream(caCertificate)) {
                X509Certificate certificate = (X509Certificate) factory.generateCertificate(in);
                KeyStore store = KeyStore.getInstance("PKCS12");
                store.load(null, null);
                store.setCertificateEntry(alias, certificate);
                try (OutputStream out = Files.newOutputStream(output)) {
                    store.store(out, PASSWORD);
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create test trust store " + output, e);
        }
    }

    private static void openssl(String... arguments) {
        List<String> command = new ArrayList<>();
        command.add(System.getenv().getOrDefault("OPENSSL", "openssl"));
        command.addAll(List.of(arguments));
        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IllegalStateException(
                        "openssl command failed (" + exitCode + "): " + command + System.lineSeparator() + output);
            }
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Unable to run openssl: " + command, e);
        }
    }

    private static void write(Path path, String content) {
        try {
            Files.writeString(path, content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to write " + path, e);
        }
    }

    private static void createDirectories(Path directory) {
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to create directory " + directory, e);
        }
    }

    private static void deleteRecursively(Path directory) {
        if (!Files.exists(directory)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(directory)) {
            List<Path> paths = walk.sorted(Comparator.reverseOrder()).toList();
            for (Path path : paths) {
                Files.deleteIfExists(path);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Unable to clean test certificate directory " + directory, e);
        }
    }
}
