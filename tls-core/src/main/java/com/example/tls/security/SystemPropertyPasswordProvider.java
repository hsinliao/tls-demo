package com.example.tls.security;

import java.util.Optional;

/**
 * Reads passwords from JVM system properties such as
 * {@code -DTLS_KEYSTORE_PASSWORD=...}. Useful for local demos and container
 * entrypoints that cannot use environment variables directly.
 */
public final class SystemPropertyPasswordProvider implements PasswordProvider {

    @Override
    public Optional<char[]> lookup(String secretName) {
        String value = System.getProperty(secretName);
        return value == null ? Optional.empty() : Optional.of(value.toCharArray());
    }

    @Override
    public String toString() {
        return "SystemPropertyPasswordProvider{}";
    }
}
