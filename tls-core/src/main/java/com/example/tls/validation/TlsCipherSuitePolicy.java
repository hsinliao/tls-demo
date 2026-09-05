package com.example.tls.validation;

import com.example.tls.config.TlsProtocols;
import com.example.tls.context.JsseCapabilities;
import com.example.tls.exception.TlsConfigurationException;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Cipher-suite policy:
 *
 * <ul>
 *   <li>No configured suites → keep the JDK 17 JSSE security defaults (the
 *       current provider's {@code SSLParameters} defaults, already filtered by
 *       {@code jdk.tls.disabledAlgorithms}). No custom list is maintained.</li>
 *   <li>Configured suites → strict whitelist. Unsupported, insecure, or
 *       protocol-incompatible entries fail fast; nothing is silently added,
 *       ignored, or replaced with defaults.</li>
 * </ul>
 */
public final class TlsCipherSuitePolicy {

    /**
     * RFC 8446 defines exactly these TLS 1.3 cipher suites. They are the only
     * suites usable with TLSv1.3; every other supported suite belongs to
     * TLS 1.2 (and older) and cannot be negotiated under TLSv1.3.
     */
    // RFC 8446 定义的全部 TLS 1.3 套件；TLSv1.2 下这些套件一律不可用。
    private static final Set<String> TLS_1_3_ONLY_SUITES = Set.of(
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256");

    // 安全策略关键字：命中任一即拒绝（大小写不敏感，按 "_" 分隔的套件名匹配）。
    private static final Set<String> FORBIDDEN_KEYWORDS = Set.of(
            "NULL", "ANON", "EXPORT", "RC4", "DES", "3DES", "MD5");

    private TlsCipherSuitePolicy() {
    }

    /**
     * Resolves the effective cipher-suite policy for a protocol list.
     *
     * @throws TlsConfigurationException when an explicitly configured suite is
     *                                   forbidden, unsupported by the runtime, or
     *                                   incompatible with the configured protocols
     */
    public static CipherSuitePlan resolve(List<String> protocols, List<String> configuredCipherSuites,
                                          JsseCapabilities capabilities) {
        if (configuredCipherSuites == null || configuredCipherSuites.isEmpty()) {
            // 未显式配置：不生成/不锁定任何白名单，原样返回 JDK 默认启用集。
            // 调用方此时不会调用 SSLParameters.setCipherSuites(...)，
            // 从而把“默认启用哪些套件”的决定权完整保留给 JSSE/安全策略。
            return CipherSuitePlan.defaults(capabilities.defaultEnabledCipherSuites());
        }

        // 协议兼容性只看“是否允许该套件所属的协议版本”，
        // 不支持把 TLS1.3-only 套件降级到 TLS1.2 使用。
        boolean allowsTls12 = protocols.contains(TlsProtocols.TLS_1_2);
        boolean allowsTls13 = protocols.contains(TlsProtocols.TLS_1_3);

        for (String suite : configuredCipherSuites) {
            // 逐个套件校验：任一非法都整体失败，不允许“部分接受、部分忽略”。
            validateSuite(suite, capabilities, allowsTls12, allowsTls13);
        }
        return CipherSuitePlan.whitelist(configuredCipherSuites);
    }

    private static void validateSuite(String suite, JsseCapabilities capabilities,
                                      boolean allowsTls12, boolean allowsTls13) {
        if (suite == null || suite.isBlank()) {
            throw new TlsConfigurationException(
                    "Configured cipher suite must not be null or blank");
        }

        String forbidden = forbiddenKeyword(suite);
        if (forbidden != null) {
            // 即使某个弱套件在当前 JVM 中已不可用，也要优先给出“安全策略拒绝”
            // 的明确信息，而不是含糊的 unsupported。
            throw new TlsConfigurationException(
                    "Configured cipher suite '" + suite + "' is rejected by the security policy "
                            + "because it contains the forbidden/insecure keyword '" + forbidden + "'");
        }

        if (!capabilities.supportedCipherSuites().contains(suite)) {
            throw new TlsConfigurationException(
                    "Configured cipher suite '" + suite + "' is not supported by JDK JSSE on this runtime. "
                            + "Supported cipher suites: " + capabilities.supportedCipherSuites().size() + " entries");
        }

        boolean tls13Only = TLS_1_3_ONLY_SUITES.contains(suite);
        if (tls13Only && !allowsTls13) {
            // RFC 8446 的 TLS_AES_*/CHACHA20 套件只能出现在 TLSv1.3 握手中。
            throw new TlsConfigurationException(
                    "Configured cipher suite '" + suite + "' is a TLS 1.3-only cipher suite "
                            + "but TLSv1.3 is not among the enabled protocols.");
        }
        if (!tls13Only && !allowsTls12) {
            // 其余受支持套件均属于 TLS1.2 兼容集合；只开 TLSv1.3 时不能使用它们。
            throw new TlsConfigurationException(
                    "Configured cipher suite '" + suite + "' can only be negotiated with TLS 1.2, "
                            + "but the enabled protocols do not include TLSv1.2. "
                            + "TLS 1.3 accepts only the RFC 8446 TLS_AES_* / TLS_CHACHA20_POLY1305 suites.");
        }
    }

    private static String forbiddenKeyword(String suite) {
        String upper = suite.toUpperCase(Locale.ROOT);
        for (String keyword : FORBIDDEN_KEYWORDS) {
            if (upper.contains(keyword)) {
                return keyword;
            }
        }
        return null;
    }
}
