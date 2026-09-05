package com.example.tls.exception;

/**
 * Base exception for all TLS foundation errors.
 *
 * <p>Messages must never contain passwords, private keys, or other secret material.
 */
public class TlsException extends RuntimeException {

    public TlsException(String message) {
        super(message);
    }

    public TlsException(String message, Throwable cause) {
        super(message, cause);
    }
}
