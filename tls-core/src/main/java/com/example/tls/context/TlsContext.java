package com.example.tls.context;

import com.example.tls.config.EndpointRole;
import com.example.tls.config.TlsConfig;
import com.example.tls.validation.CipherSuitePlan;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * One immutable, independently created {@link SSLContext} together with the
 * configuration and effective parameters it was built from. Instances are never
 * shared with the JVM-global default context.
 */
public final class TlsContext {

    private static final AtomicLong IDS = new AtomicLong(); // context 实例 id 生成器（观测/轮换用）

    private final long id;                     // 单调递增实例 id
    private final SSLContext sslContext;       // 真正用于创建 socket 的 JSSE context
    private final TlsConfig config;            // 构建本实例使用的原始配置快照
    private final EndpointRole role;           // SERVER/CLIENT，决定 EKU 与 store 校验语义
    private final List<String> effectiveProtocols; // 校验后生效的协议列表
    private final CipherSuitePlan cipherSuitePlan; // 校验后的 cipher 计划（默认或白名单）
    private final Instant createdAt;           // 创建时间，用于轮换与可观测性

    TlsContext(SSLContext sslContext, TlsConfig config, EndpointRole role,
               List<String> effectiveProtocols, CipherSuitePlan cipherSuitePlan) {
        this.id = IDS.incrementAndGet();
        this.sslContext = sslContext;
        this.config = config;
        this.role = role;
        this.effectiveProtocols = List.copyOf(effectiveProtocols);
        this.cipherSuitePlan = cipherSuitePlan;
        this.createdAt = Instant.now();
    }

    /** Monotonically increasing instance id useful for rotation/observability. */
    public long id() {
        return id;
    }

    public SSLContext sslContext() {
        return sslContext;
    }

    public TlsConfig config() {
        return config;
    }

    public EndpointRole role() {
        return role;
    }

    public List<String> effectiveProtocols() {
        return effectiveProtocols;
    }

    public List<String> effectiveCipherSuites() {
        return cipherSuitePlan.cipherSuites();
    }

    public boolean cipherSuitesExplicitlyConfigured() {
        return cipherSuitePlan.explicit();
    }

    public Instant createdAt() {
        return createdAt;
    }

    public SSLSocketFactory socketFactory() {
        return sslContext.getSocketFactory();
    }

    public SSLServerSocketFactory serverSocketFactory() {
        return sslContext.getServerSocketFactory();
    }
}
