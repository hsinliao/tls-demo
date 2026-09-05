package com.example.tls.observability;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.Collectors;

/**
 * Thread-safe counters for handshake attempts, successes, and failures,
 * including per-protocol and per-cipher-suite breakdowns.
 */
public final class TlsMetrics implements TlsHandshakeObserver {

    private final AtomicLong handshakeAttempts = new AtomicLong();  // 握手尝试总数
    private final AtomicLong handshakeSuccesses = new AtomicLong(); // 成功总数
    private final AtomicLong handshakeFailures = new AtomicLong();  // 失败总数
    private final ConcurrentHashMap<String, LongAdder> successesByProtocol = new ConcurrentHashMap<>();     // 成功数按协议分布
    private final ConcurrentHashMap<String, LongAdder> successesByCipherSuite = new ConcurrentHashMap<>(); // 成功数按套件分布

    /** Immutable point-in-time snapshot. */
    public record Snapshot(
            long handshakeAttempts,       // 尝试总数
            long handshakeSuccesses,      // 成功总数
            long handshakeFailures,       // 失败总数
            Map<String, Long> successesByProtocol,     // 成功数按协议快照
            Map<String, Long> successesByCipherSuite) { // 成功数按套件快照
    }

    public static TlsMetrics create() {
        return new TlsMetrics();
    }

    @Override
    public void onHandshakeStarted(HandshakeAttempt attempt) {
        handshakeAttempts.incrementAndGet();
    }

    @Override
    public void onHandshakeSucceeded(HandshakeInfo info) {
        handshakeSuccesses.incrementAndGet();
        successesByProtocol.computeIfAbsent(info.protocol(), ignored -> new LongAdder()).increment();
        successesByCipherSuite.computeIfAbsent(info.cipherSuite(), ignored -> new LongAdder()).increment();
    }

    @Override
    public void onHandshakeFailed(HandshakeFailure failure) {
        handshakeFailures.incrementAndGet();
    }

    public long handshakeAttempts() {
        return handshakeAttempts.get();
    }

    public long handshakeSuccesses() {
        return handshakeSuccesses.get();
    }

    public long handshakeFailures() {
        return handshakeFailures.get();
    }

    public Snapshot snapshot() {
        return new Snapshot(
                handshakeAttempts.get(),
                handshakeSuccesses.get(),
                handshakeFailures.get(),
                copyCounts(successesByProtocol),
                copyCounts(successesByCipherSuite));
    }

    private static Map<String, Long> copyCounts(Map<String, LongAdder> source) {
        return source.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, e -> e.getValue().sum()));
    }
}
