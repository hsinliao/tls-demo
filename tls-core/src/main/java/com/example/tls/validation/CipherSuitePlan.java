package com.example.tls.validation;

import java.util.List;

/**
 * Result of cipher-suite policy resolution.
 *
 * <p>{@code explicit == false} means no suites were configured, so JSSE keeps
 * the JDK security defaults and the list is only informational.
 */
public record CipherSuitePlan(List<String> cipherSuites, // 生效的套件列表（默认集或严格白名单）
                              boolean explicit) {        // true=用户显式配置的白名单

    public CipherSuitePlan {
        cipherSuites = List.copyOf(cipherSuites);
    }

    public static CipherSuitePlan defaults(List<String> cipherSuites) {
        return new CipherSuitePlan(cipherSuites, false);
    }

    public static CipherSuitePlan whitelist(List<String> cipherSuites) {
        return new CipherSuitePlan(cipherSuites, true);
    }
}
