package com.example.tls.security;

import com.example.tls.exception.TlsConfigurationException;

import java.util.Optional;

/**
 * Resolves a secret (usually a keystore/truststore password) by a symbolic name
 * such as {@code TLS_KEYSTORE_PASSWORD}.
 *
 * <p>Implementations must never log, serialize, or expose the returned value in
 * exception messages. The demo ships environment/system-property providers;
 * production code should back this interface with Secret Manager, Kubernetes
 * Secrets, Vault, KMS, HSM, or similar.
 */
@FunctionalInterface
public interface PasswordProvider {

    /**
     * Looks up a secret.
     *
     * @param secretName symbolic secret key
     * @return the secret characters, or empty when this provider has no value
     */
    Optional<char[]> lookup(String secretName);

    /**
     * Required lookup used by TLS initialization.
     *
     * @throws TlsConfigurationException when no configured provider has the secret
     */
    default char[] resolve(String secretName) {
        Optional<char[]> value = lookup(secretName);
        if (value.isEmpty()) {
            // 故意不回显任何候选值/长度，只给出缺失的符号名与注入方式。
            throw new TlsConfigurationException(
                    "No password is available for secret name '" + secretName
                            + "'. Configure it through an environment variable or system property.");
        }
        return value.get();
    }
}
