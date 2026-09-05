package com.example.tls.observability;

import com.example.tls.config.EndpointRole;

import java.time.Instant;

/** A handshake that is about to start. Contains no secrets. */
public record HandshakeAttempt(
        EndpointRole role,   // 发起方角色：SERVER/CLIENT
        String peerHost,     // 对端标识（client 为配置主机名，server 为远程 IP）
        int peerPort,        // 对端端口
        Instant startedAt) { // 握手开始时间
}
