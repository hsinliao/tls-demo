package com.example.tls.context;

/**
 * Supplies the current {@link TlsContext} and supports atomic rotation.
 *
 * <p>Rotation semantics: existing connections continue on the SSLContext used
 * for their handshake; only new connections observe the reloaded context.
 */
public interface TlsContextProvider {

    /** Current context used for new connections. */
    TlsContext current();

    /**
     * Reloads configuration/certificates and atomically publishes a new context.
     *
     * @return the newly published context
     * @throws com.example.tls.exception.TlsException when the new context cannot
     *         be created; the previous context remains active in that case
     */
    TlsContext reload();
}
