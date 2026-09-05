package com.example.tls.exception;

/**
 * Invalid, incomplete, or contradictory TLS configuration. Thrown before a TLS
 * endpoint is started (fail fast).
 */
public class TlsConfigurationException extends TlsException {

    public TlsConfigurationException(String message) {
        super(message);
    }

    public TlsConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
