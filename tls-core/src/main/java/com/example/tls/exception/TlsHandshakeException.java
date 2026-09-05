package com.example.tls.exception;

/**
 * TLS handshake failure, including authentication, protocol, certificate, and
 * cipher-suite negotiation failures.
 */
public class TlsHandshakeException extends TlsException {

    public TlsHandshakeException(String message) {
        super(message);
    }

    public TlsHandshakeException(String message, Throwable cause) {
        super(message, cause);
    }
}
