package com.example.tls.exception;

/**
 * Failure while building an {@link javax.net.ssl.SSLContext} or a TLS endpoint.
 */
public class TlsInitializationException extends TlsException {

    public TlsInitializationException(String message) {
        super(message);
    }

    public TlsInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
