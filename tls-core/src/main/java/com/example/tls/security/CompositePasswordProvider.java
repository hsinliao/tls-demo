package com.example.tls.security;

import java.util.List;
import java.util.Optional;

/**
 * Tries providers in order and returns the first hit. The demo uses
 * environment variables first, then JVM system properties.
 */
public final class CompositePasswordProvider implements PasswordProvider {

    private final List<PasswordProvider> providers; // 按顺序尝试的密码提供器

    private CompositePasswordProvider(List<PasswordProvider> providers) {
        this.providers = List.copyOf(providers);
    }

    public static PasswordProvider of(PasswordProvider... providers) {
        if (providers == null || providers.length == 0) {
            throw new IllegalArgumentException("At least one password provider is required");
        }
        return new CompositePasswordProvider(List.of(providers));
    }

    @Override
    public Optional<char[]> lookup(String secretName) {
        for (PasswordProvider provider : providers) {
            Optional<char[]> value = provider.lookup(secretName);
            if (value.isPresent()) {
                return value;
            }
        }
        return Optional.empty();
    }

    @Override
    public String toString() {
        return "CompositePasswordProvider{providers=" + providers.size() + "}";
    }
}
