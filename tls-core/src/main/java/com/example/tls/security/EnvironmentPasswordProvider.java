package com.example.tls.security;

import java.util.Optional;

/**
 * Reads passwords from process environment variables. The secret name is used
 * verbatim as the environment variable name, e.g. {@code TLS_KEYSTORE_PASSWORD}.
 */
public final class EnvironmentPasswordProvider implements PasswordProvider {

    @Override
    public Optional<char[]> lookup(String secretName) {
        String value = System.getenv(secretName);
        return value == null ? Optional.empty() : Optional.of(value.toCharArray());
    }

    @Override
    public String toString() {
        return "EnvironmentPasswordProvider{}";
    }
}
