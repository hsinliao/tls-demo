package com.example.tls.connection;

import com.example.tls.observability.HandshakeInfo;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * A transport-level TLS connection. The core interface intentionally exposes
 * raw byte streams only; record framing (line-based, length-prefixed, protobuf,
 * ...) belongs to the application layer.
 *
 * <p>Callers own this resource and must call {@link #close()} (preferably via
 * try-with-resources). Closing the underlying socket also releases the streams.
 */
public interface TlsConnection extends AutoCloseable {

    /** Sanitized handshake metadata captured after a successful handshake. */
    HandshakeInfo handshakeInfo();

    /** Input stream for reading decrypted application data. */
    InputStream inputStream();

    /** Output stream for writing decrypted application data. */
    OutputStream outputStream();

    boolean isClosed();

    @Override
    void close();
}
