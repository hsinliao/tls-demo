package com.example.tls.certificate;

import com.example.tls.config.StoreConfig;
import com.example.tls.exception.TlsCertificateException;
import com.example.tls.exception.TlsConfigurationException;
import com.example.tls.security.PasswordProvider;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Loads PKCS12/JKS stores and extracts private-key entries or trusted
 * certificates. Password values are only obtained through a
 * {@link PasswordProvider}; they are never stored in configuration objects.
 */
public final class KeyStoreLoader {

    private KeyStoreLoader() {
    }

    /** Details of a usable private-key entry (server or client identity). */
    public record PrivateKeyEntryDetails(
            String alias,                  // 命中私钥条目的 alias（观测/排障用）
            PrivateKey privateKey,         // 私钥对象；仅在 JVM 内存中使用
            List<X509Certificate> chain) { // 条目证书链，叶子在首位
    }

    /**
     * Loads an existing store.
     *
     * @param spec        store location/type/password key
     * @param description human-readable kind, e.g. "server key store"
     * @param passwords   runtime secret source
     */
    public static KeyStore loadStore(StoreConfig spec, String description, PasswordProvider passwords) {
        try {
            char[] storePassword = passwords.resolve(spec.passwordKey());
            if (spec.isFileBased()) {
                Path path = spec.path();
                if (!Files.isRegularFile(path)) {
                    throw new TlsConfigurationException(
                            description + " file does not exist or is not a regular file: "
                                    + path.toAbsolutePath());
                }
                KeyStore store = KeyStore.getInstance(spec.type());
                try (InputStream in = Files.newInputStream(path)) {
                    store.load(in, storePassword);
                }
                return store;
            }

            // Provider-backed store（PKCS#11 / HSM / 未来 KMS provider）：
            // 无文件流，直接 load(null, tokenPin)。providerName 用于多实例选择。
            KeyStore providerStore = spec.providerName() == null
                    ? KeyStore.getInstance(spec.type())
                    : KeyStore.getInstance(spec.type(), spec.providerName());
            providerStore.load(null, storePassword);
            return providerStore;
        } catch (KeyStoreException | NoSuchProviderException e) {
            throw new TlsConfigurationException(
                    "Unsupported " + description + " type '" + spec.type()
                            + "' / provider '" + spec.providerName()
                            + "'. Supported types depend on the registered JCE providers.", e);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new TlsCertificateException(
                    "Failed to load " + description + " (file=" + spec.path()
                            + ", provider=" + spec.providerName()
                            + ") — wrong password/PIN, uninitialized token, or unsupported content", e);
        }
    }

    /**
     * Finds exactly one private-key entry. A preferred alias is honored when it
     * exists; otherwise the store must contain exactly one key entry.
     */
    public static String findKeyEntryAlias(KeyStore store, String preferredAlias) {
        try {
            if (preferredAlias != null) {
                if (!store.containsAlias(preferredAlias) || !store.isKeyEntry(preferredAlias)) {
                    throw new TlsCertificateException(
                            "Store does not contain a private-key entry with alias '" + preferredAlias + "'");
                }
                return preferredAlias;
            }

            List<String> keyAliases = new ArrayList<>();
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (store.isKeyEntry(alias)) {
                    keyAliases.add(alias);
                }
            }
            if (keyAliases.isEmpty()) {
                // 常见误用：把只含受信 CA 的 TrustStore 配到了 keyStore 位置。
                throw new TlsCertificateException(
                        "Store does not contain a PrivateKeyEntry. Load an identity store, not a trust store.");
            }
            if (keyAliases.size() > 1) {
                // 多 identity 库必须显式 alias，避免加载到错误的私钥。
                throw new TlsCertificateException(
                        "Store contains " + keyAliases.size()
                                + " private-key entries; configure StoreConfig.alias to select one.");
            }
            return keyAliases.get(0);
        } catch (KeyStoreException e) {
            throw new TlsCertificateException("Unable to inspect key store aliases", e);
        }
    }

    /**
     * Extracts the private key and its certificate chain. PKCS12 normally uses
     * the store password as the entry password; legacy JKS may use the separate
     * {@code keyPasswordKey} configured on the store.
     */
    public static PrivateKeyEntryDetails privateKeyEntry(KeyStore store, String alias,
                                                         PasswordProvider passwords, StoreConfig spec) {
        // Provider/HSM 私钥通常由 token 保护，不把 PIN 再次当条目口令传入。
        char[] keyPassword = spec.isProviderBased()
                ? null
                : passwords.resolve(spec.effectiveKeyPasswordKey());
        try {
            Key key = store.getKey(alias, keyPassword);
            if (!(key instanceof PrivateKey privateKey)) {
                throw new TlsCertificateException("Alias '" + alias + "' does not contain a private key");
            }
            Certificate[] rawChain = store.getCertificateChain(alias);
            if (rawChain == null || rawChain.length == 0) {
                throw new TlsCertificateException("Alias '" + alias + "' has no certificate chain");
            }
            List<X509Certificate> chain = new ArrayList<>(rawChain.length);
            for (Certificate certificate : rawChain) {
                if (!(certificate instanceof X509Certificate x509)) {
                    throw new TlsCertificateException(
                            "Alias '" + alias + "' chain contains a non-X.509 certificate: " + certificate.getType());
                }
                chain.add(x509);
            }
            return new PrivateKeyEntryDetails(alias, privateKey, List.copyOf(chain));
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new TlsCertificateException(
                    "Unable to read private key entry '" + alias + "' (wrong key password?)", e);
        }
    }

    /** All trusted (CA/intermediate) certificates in a store. */
    public static List<X509Certificate> trustedCertificates(KeyStore store) {
        List<X509Certificate> trusted = new ArrayList<>();
        try {
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (store.isCertificateEntry(alias)) {
                    Certificate certificate = store.getCertificate(alias);
                    if (certificate instanceof X509Certificate x509) {
                        trusted.add(x509);
                    }
                }
            }
        } catch (KeyStoreException e) {
            throw new TlsCertificateException("Unable to inspect trust store entries", e);
        }
        if (trusted.isEmpty()) {
            throw new TlsCertificateException(
                    "Trust store does not contain any trusted certificate entries.");
        }
        return List.copyOf(trusted);
    }
}
