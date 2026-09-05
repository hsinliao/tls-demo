package com.example.tls.observability;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;

/**
 * Default handshake logger. Logs sanitized connection metadata only; never
 * passwords, private keys, or session secrets.
 */
public final class LoggingTlsHandshakeObserver implements TlsHandshakeObserver {

    private final Logger logger = System.getLogger(LoggingTlsHandshakeObserver.class.getName()); // JDK System.Logger 后端

    @Override
    public void onHandshakeStarted(HandshakeAttempt attempt) {
        logger.log(Level.DEBUG,
                "TLS handshake started role={0} peer={1}:{2}",
                attempt.role(), attempt.peerHost(), attempt.peerPort());
    }

    @Override
    public void onHandshakeSucceeded(HandshakeInfo info) {
        // 只输出脱敏握手元数据；subject/issuer 是证书中的公钥信息，
        // 不含私钥、口令或会话密钥。
        logger.log(Level.INFO,
                "TLS handshake succeeded role={0} peer={1}:{2} protocol={3} cipherSuite={4} "
                        + "peerCertificatePresent={5} peerSubject={6} peerIssuer={7} alpn={8}",
                info.role(), info.peerHost(), info.peerPort(),
                info.protocol(), info.cipherSuite(), info.peerCertificatesPresent(),
                quoted(info.peerSubjectDn()), quoted(info.peerIssuerDn()),
                quoted(info.applicationProtocol()));
    }

    @Override
    public void onHandshakeFailed(HandshakeFailure failure) {
        HandshakeAttempt attempt = failure.attempt();
        logger.log(Level.WARNING,
                "TLS handshake failed role={0} peer={1}:{2} exceptionType={3} message={4}",
                attempt.role(), attempt.peerHost(), attempt.peerPort(),
                failure.exceptionType(), quoted(failure.message()));
    }

    private static String quoted(String value) {
        return value == null ? "" : "\"" + value + "\"";
    }
}
