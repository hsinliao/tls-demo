package com.example.tls.observability;

import java.time.Instant;

/** Sanitized description of a failed handshake. */
public record HandshakeFailure(
        HandshakeAttempt attempt, // 失败对应的握手尝试（含角色/对端）
        String exceptionType,     // 异常类型简名，如 SSLHandshakeException
        String message,           // 脱敏后的失败原因（不含密钥/口令）
        Instant failedAt) {       // 失败时间
}
