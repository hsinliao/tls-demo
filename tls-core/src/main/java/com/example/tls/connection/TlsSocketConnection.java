package com.example.tls.connection;

import com.example.tls.config.EndpointRole;
import com.example.tls.exception.TlsConnectionException;
import com.example.tls.exception.TlsHandshakeException;
import com.example.tls.observability.HandshakeAttempt;
import com.example.tls.observability.HandshakeFailure;
import com.example.tls.observability.HandshakeInfo;
import com.example.tls.observability.TlsHandshakeObserver;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * JSSE-backed, framing-agnostic {@link TlsConnection}.
 *
 * <p>Handshake timeout and application read timeout are separated: the
 * {@code SO_TIMEOUT} is set to the handshake timeout before
 * {@code startHandshake()}, then switched to the socket timeout afterwards.
 */
public final class TlsSocketConnection implements TlsConnection {

    private final SSLSocket socket;            // 已握手（或正在握手）的底层 SSLSocket
    private final HandshakeInfo handshakeInfo; // 握手成功后固定的脱敏观测信息
    private final InputStream input;           // 解密后的应用输入流
    private final OutputStream output;         // 加密前的应用输出流
    private final AtomicBoolean closed = new AtomicBoolean(); // close 幂等标记

    private TlsSocketConnection(SSLSocket socket, HandshakeInfo handshakeInfo) throws IOException {
        this.socket = socket;
        this.handshakeInfo = handshakeInfo;
        this.input = socket.getInputStream();
        this.output = socket.getOutputStream();
    }

    /**
     * Runs the TLS handshake and returns a transport connection.
     *
     * @throws TlsHandshakeException on alert/certificate/protocol/timeout failures
     * @throws TlsConnectionException on lower-level I/O failure
     */
    public static TlsSocketConnection establish(SSLSocket ssl, EndpointRole role, String peerHost, int peerPort,
                                                Duration handshakeTimeout, Duration socketReadTimeout,
                                                List<TlsHandshakeObserver> observers) {
        HandshakeAttempt attempt =
                new HandshakeAttempt(role, peerHost, peerPort, Instant.now());
        notifyStarted(observers, attempt);

        try {
            // 先用手超时启动握手：JSSE 在 SO_TIMEOUT 内未完成握手会抛 SocketTimeoutException。
            ssl.setSoTimeout(toIntTimeout(handshakeTimeout, "handshakeTimeout"));
            ssl.startHandshake();
            HandshakeInfo info = capture(ssl, role, peerHost, peerPort);
            // 握手成功后立刻把读超时切到“业务读超时”，两者语义必须分开。
            ssl.setSoTimeout(toIntTimeout(socketReadTimeout, "socketTimeout"));
            TlsSocketConnection connection = new TlsSocketConnection(ssl, info);
            notifySuccess(observers, info);
            return connection;
        } catch (SSLException | SocketTimeoutException e) {
            notifyFailure(observers, attempt, e);
            closeQuietly(ssl);
            throw new TlsHandshakeException(
                    "TLS handshake with " + peerHost + ":" + peerPort + " failed: " + e.getMessage(), e);
        } catch (IOException e) {
            notifyFailure(observers, attempt, e);
            closeQuietly(ssl);
            throw new TlsConnectionException(
                    "I/O failure during TLS handshake with " + peerHost + ":" + peerPort + ": " + e.getMessage(), e);
        } catch (RuntimeException e) {
            notifyFailure(observers, attempt, e);
            closeQuietly(ssl);
            throw e;
        }
    }

    private static HandshakeInfo capture(SSLSocket ssl, EndpointRole role,
                                         String peerHost, int peerPort) {
        SSLSession session = ssl.getSession();
        boolean peerCertificatesPresent = false;
        boolean localCertificatesPresent = session.getLocalCertificates() != null
                && session.getLocalCertificates().length > 0;
        String peerSubject = null;
        String peerIssuer = null;
        try {
            Certificate[] peerCertificates = session.getPeerCertificates();
            if (peerCertificates != null && peerCertificates.length > 0
                    && peerCertificates[0] instanceof X509Certificate peerLeaf) {
                // 取链首叶子证书用于脱敏观测；链校验本身已由 JSSE TrustManager 完成。
                peerCertificatesPresent = true;
                peerSubject = String.valueOf(peerLeaf.getSubjectX500Principal());
                peerIssuer = String.valueOf(peerLeaf.getIssuerX500Principal());
            }
        } catch (SSLPeerUnverifiedException ignored) {
            // 对端未提供证书（例如服务端 NONE 模式下观察到的匿名客户端），
            // 这是合法状态，不是错误。
        }

        return new HandshakeInfo(
                role,
                peerHost,
                peerPort,
                String.valueOf(ssl.getLocalSocketAddress()),
                String.valueOf(ssl.getRemoteSocketAddress()),
                session.getProtocol(),
                session.getCipherSuite(),
                peerCertificatesPresent,
                localCertificatesPresent,
                peerSubject,
                peerIssuer,
                ssl.getApplicationProtocol(),
                Instant.now());
    }

    @Override
    public HandshakeInfo handshakeInfo() {
        return handshakeInfo;
    }

    @Override
    public InputStream inputStream() {
        ensureOpen();
        return input;
    }

    @Override
    public OutputStream outputStream() {
        ensureOpen();
        return output;
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new TlsConnectionException(
                    "TLS connection to " + handshakeInfo.peerHost() + ":" + handshakeInfo.peerPort()
                            + " is closed");
        }
    }

    @Override
    public boolean isClosed() {
        return closed.get() || socket.isClosed();
    }

    @Override
    public void close() {
        // 幂等关闭：同一连接被 Server 与业务代码同时 close 也不会双关报错。
        if (closed.compareAndSet(false, true)) {
            closeQuietly(socket);
        }
    }

    private static void notifyStarted(List<TlsHandshakeObserver> observers, HandshakeAttempt attempt) {
        for (TlsHandshakeObserver observer : observers) {
            observer.onHandshakeStarted(attempt);
        }
    }

    private static void notifySuccess(List<TlsHandshakeObserver> observers, HandshakeInfo info) {
        for (TlsHandshakeObserver observer : observers) {
            observer.onHandshakeSucceeded(info);
        }
    }

    private static void notifyFailure(List<TlsHandshakeObserver> observers,
                                      HandshakeAttempt attempt, Exception failure) {
        HandshakeFailure event = new HandshakeFailure(
                attempt, failure.getClass().getSimpleName(), failure.getMessage(), Instant.now());
        for (TlsHandshakeObserver observer : observers) {
            observer.onHandshakeFailed(event);
        }
    }

    private static int toIntTimeout(Duration duration, String field) {
        try {
            return Math.toIntExact(duration.toMillis());
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(field + " is too large: " + duration.toMillis() + "ms");
        }
    }

    private static void closeQuietly(SSLSocket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Already closed or concurrently closed; nothing further to release.
        }
    }
}
