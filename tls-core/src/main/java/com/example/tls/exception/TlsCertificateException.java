package com.example.tls.exception;

/**
 * Certificate loading, expiry, extension, or keystore/truststore problems.
 */
public class TlsCertificateException extends TlsException {

    public TlsCertificateException(String message) {
        super(message);
    }

    public TlsCertificateException(String message, Throwable cause) {
        super(message, cause);
    }
}
