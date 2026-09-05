package com.example.tls.observability;

import com.example.tls.config.EndpointRole;

import java.time.Instant;

/**
 * Sanitized, loggable result of a successful TLS handshake. Subject/issuer DNs,
 * protocol, and cipher suite are included; passwords, private keys, session
 * keys, and raw secret material are never included.
 */
public record HandshakeInfo(
        EndpointRole role,                // 本端角色
        String peerHost,                  // 对端主机标识
        int peerPort,                     // 对端端口
        String localAddress,              // 本端 socket 地址（含端口）
        String remoteAddress,             // 对端 socket 地址（含端口）
        String protocol,                  // 实际协商协议，如 TLSv1.3
        String cipherSuite,               // 实际协商套件，如 TLS_AES_256_GCM_SHA384
        boolean peerCertificatesPresent,  // 对端是否提供了证书
        boolean localCertificatesPresent, // 本端是否向对端提供了证书
        String peerSubjectDn,             // 对端叶子证书 Subject DN（脱敏后用于日志）
        String peerIssuerDn,              // 对端叶子证书 Issuer DN
        String applicationProtocol,       // ALPN 结果，未协商时为空串
        Instant timestamp) {              // 握手成功时间
}
