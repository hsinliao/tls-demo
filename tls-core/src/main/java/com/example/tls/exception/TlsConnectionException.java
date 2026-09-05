package com.example.tls.exception;

/**
 * I/O failure on an established TCP/TLS connection (send, receive, or close).
 */
public class TlsConnectionException extends TlsException {

    public TlsConnectionException(String message) {
        super(message);
    }

    public TlsConnectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
