package com.example.tls.observability;

/**
 * Observability hook for TLS handshakes. Implementations must never log or
 * retain secret material; the event records contain only connection metadata.
 */
public interface TlsHandshakeObserver {

    default void onHandshakeStarted(HandshakeAttempt attempt) {
    }

    default void onHandshakeSucceeded(HandshakeInfo info) {
    }

    default void onHandshakeFailed(HandshakeFailure failure) {
    }
}
