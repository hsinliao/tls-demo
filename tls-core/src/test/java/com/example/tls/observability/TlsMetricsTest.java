package com.example.tls.observability;

import com.example.tls.config.EndpointRole;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TlsMetricsTest {

    @Test
    void metricsCountsHandshakeOutcomes() {
        TlsMetrics metrics = TlsMetrics.create();
        HandshakeAttempt attempt = new HandshakeAttempt(EndpointRole.CLIENT, "localhost", 8443, Instant.now());

        metrics.onHandshakeStarted(attempt);
        metrics.onHandshakeStarted(attempt);
        metrics.onHandshakeSucceeded(new HandshakeInfo(
                EndpointRole.CLIENT, "localhost", 8443, "local", "remote",
                "TLSv1.3", "TLS_AES_256_GCM_SHA384", true, true,
                "CN=server", "CN=ca", "", Instant.now()));
        metrics.onHandshakeSucceeded(new HandshakeInfo(
                EndpointRole.CLIENT, "localhost", 8443, "local", "remote",
                "TLSv1.3", "TLS_AES_256_GCM_SHA384", true, true,
                "CN=server", "CN=ca", "", Instant.now()));
        metrics.onHandshakeFailed(new HandshakeFailure(attempt, "SSLHandshakeException",
                "bad certificate", Instant.now()));

        assertEquals(2, metrics.handshakeAttempts());
        assertEquals(2, metrics.handshakeSuccesses());
        assertEquals(1, metrics.handshakeFailures());
        TlsMetrics.Snapshot snapshot = metrics.snapshot();
        assertEquals(2L, snapshot.successesByProtocol().get("TLSv1.3"));
        assertEquals(2L, snapshot.successesByCipherSuite().get("TLS_AES_256_GCM_SHA384"));
        assertTrue(snapshot.successesByCipherSuite().containsKey("TLS_AES_256_GCM_SHA384"));
    }
}
