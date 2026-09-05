package com.example.tls.config;

import java.util.Objects;

/**
 * Immutable holder for the {@link ClientAuthMode}. The nested shape keeps the
 * configuration source (for example {@code clientAuthentication.mode}) explicit
 * instead of collapsing into a boolean or a bare string.
 */
public record ClientAuthentication(ClientAuthMode mode) { // mode：客户端认证策略 NONE/WANT/NEED

    public static final ClientAuthentication NONE = new ClientAuthentication(ClientAuthMode.NONE);
    public static final ClientAuthentication WANT = new ClientAuthentication(ClientAuthMode.WANT);
    public static final ClientAuthentication NEED = new ClientAuthentication(ClientAuthMode.NEED);

    public ClientAuthentication {
        Objects.requireNonNull(mode, "client authentication mode must not be null");
    }

    public static ClientAuthentication of(ClientAuthMode mode) {
        return new ClientAuthentication(mode);
    }
}
