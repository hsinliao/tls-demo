package com.example.tls.connection;

import com.example.tls.exception.TlsConnectionException;
import com.example.tls.observability.HandshakeInfo;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

/**
 * Optional application-layer adapter that adds UTF-8 line framing on top of a
 * transport-level {@link TlsConnection}. The core interface stays transport
 * oriented; applications may use this adapter, length-prefixed frames, or any
 * other protocol without changing TLS code.
 *
 * <p>{@link #close()} delegates to the underlying connection, so both can be
 * used in try-with-resources without double-close errors.
 */
public final class LineTlsConnection implements AutoCloseable {

    /** 默认单行最大字符数（约 1 MiB），防止无换行输入无限占用内存。 */
    public static final int DEFAULT_MAX_LINE_LENGTH = 1024 * 1024;

    private final TlsConnection delegate;
    private final Object lock = new Object();
    private BufferedReader reader;
    private BufferedWriter writer;
    private boolean streamsReady;

    public LineTlsConnection(TlsConnection delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    public static LineTlsConnection wrap(TlsConnection delegate) {
        return new LineTlsConnection(delegate);
    }

    public HandshakeInfo handshakeInfo() {
        return delegate.handshakeInfo();
    }

    /** Sends one UTF-8 line (newline terminated and flushed). */
    public void sendLine(String message) throws TlsConnectionException {
        if (message == null) {
            throw new IllegalArgumentException("message must not be null");
        }
        synchronized (lock) {
            ensureStreams();
            try {
                writer.write(message);
                writer.newLine();
                writer.flush();
            } catch (IOException e) {
                delegate.close();
                throw new TlsConnectionException(
                        "Unable to send data to " + delegate.handshakeInfo().peerHost()
                                + ":" + delegate.handshakeInfo().peerPort(), e);
            }
        }
    }

    /**
     * Receives one line.
     *
     * @return empty when the peer closed the connection (EOF)
     */
    public Optional<String> receiveLine() throws TlsConnectionException {
        return receiveLine(DEFAULT_MAX_LINE_LENGTH);
    }

    /** Receives one line, bounded by {@code maxCharacters}. */
    public Optional<String> receiveLine(int maxCharacters) throws TlsConnectionException {
        if (maxCharacters <= 0) {
            throw new IllegalArgumentException("maxCharacters must be positive");
        }
        synchronized (lock) {
            ensureStreams();
            try {
                StringBuilder line = new StringBuilder();
                int value;
                while ((value = reader.read()) != -1) {
                    char current = (char) value;
                    if (current == '\n') {
                        break;
                    }
                    if (current == '\r') {
                        // 兼容 CRLF：若紧接换行则结束；否则按普通字符处理。
                        reader.mark(1);
                        int next = reader.read();
                        if (next == -1 || next == '\n') {
                            break;
                        }
                        reader.reset();
                    }
                    if (line.length() >= maxCharacters) {
                        throw new TlsConnectionException(
                                "Received line from " + delegate.handshakeInfo().peerHost()
                                        + ":" + delegate.handshakeInfo().peerPort()
                                        + " exceeds max length " + maxCharacters + " characters");
                    }
                    line.append(current);
                }
                if (value == -1 && line.length() == 0) {
                    return Optional.empty();
                }
                return Optional.of(line.toString());
            } catch (IOException e) {
                delegate.close();
                throw new TlsConnectionException(
                        "Unable to receive data from " + delegate.handshakeInfo().peerHost()
                                + ":" + delegate.handshakeInfo().peerPort(), e);
            }
        }
    }

    public boolean isClosed() {
        return delegate.isClosed();
    }

    @Override
    public void close() {
        delegate.close();
    }

    private void ensureStreams() {
        if (!streamsReady) {
            this.reader = new BufferedReader(
                    new InputStreamReader(delegate.inputStream(), StandardCharsets.UTF_8));
            this.writer = new BufferedWriter(
                    new OutputStreamWriter(delegate.outputStream(), StandardCharsets.UTF_8));
            this.streamsReady = true;
        }
    }
}
