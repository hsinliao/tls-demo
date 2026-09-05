package com.example.tls.context;

import com.example.tls.config.EndpointRole;
import com.example.tls.config.TlsConfig;
import com.example.tls.security.PasswordProvider;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Default {@link TlsContextProvider}. Configuration is obtained through a
 * {@link Supplier} so certificate/key-store rotation can be expressed by
 * changing the supplied configuration and calling {@link #reload()}.
 *
 * <p>{@link AtomicReference} publication means a failed reload never replaces a
 * working context: the new {@link TlsContext} is fully created and validated
 * before {@code AtomicReference.set(...)}.
 */
public final class DefaultTlsContextProvider implements TlsContextProvider {

    private final Supplier<TlsConfig> configSupplier; // 每次 reload 重新读取配置的来源
    private final PasswordProvider passwords;        // 密码符号名解析器（不含明文）
    private final EndpointRole role;                 // 本 provider 服务的角色
    private final AtomicReference<TlsContext> current; // 原子发布当前可用 context

    public DefaultTlsContextProvider(TlsConfig initialConfig, PasswordProvider passwords, EndpointRole role) {
        this(() -> initialConfig, passwords, role);
    }

    public DefaultTlsContextProvider(Supplier<TlsConfig> configSupplier,
                                     PasswordProvider passwords, EndpointRole role) {
        this.configSupplier = Objects.requireNonNull(configSupplier, "configSupplier");
        this.passwords = Objects.requireNonNull(passwords, "passwords");
        this.role = Objects.requireNonNull(role, "role");
        // 构造即加载并校验第一个 SSLContext（fail-fast），避免“第一笔流量才报错”。
        this.current = new AtomicReference<>(TlsContextFactory.create(configSupplier.get(), role, passwords));
    }

    @Override
    public TlsContext current() {
        return current.get();
    }

    @Override
    public TlsContext reload() {
        // buildNewContext() 抛异常时不会走到 set()，旧 context 自动保持 active。
        return publishNewContext(buildNewContext());
    }

    /**
     * Builds and validates a new context without publishing it. Used by
     * endpoints that must first prove the replacement can be installed (for
     * example rebinding a server listener) before making it current.
     */
    public TlsContext buildNewContext() {
        return TlsContextFactory.create(configSupplier.get(), role, passwords);
    }

    /** Atomically publishes a previously built context. */
    public TlsContext publishNewContext(TlsContext context) {
        // AtomicReference 保证并发读取端看到的是完整、已验证的新 context。
        current.set(context);
        return context;
    }
}
