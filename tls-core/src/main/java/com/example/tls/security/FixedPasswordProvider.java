package com.example.tls.security;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory password provider for tests and local development only. Never use
 * it in production; prefer environment variables, secret managers, KMS, or HSM.
 */
public final class FixedPasswordProvider implements PasswordProvider {

    private final Map<String, String> passwords; // 符号名→明文映射，仅测试/开发使用

    private FixedPasswordProvider(Map<String, String> passwords) {
        this.passwords = Map.copyOf(passwords);
    }

    public static PasswordProvider of(Map<String, String> passwords) {
        return new FixedPasswordProvider(passwords);
    }

    public static PasswordProvider of(String secretName, String password) {
        Map<String, String> map = new HashMap<>();
        map.put(secretName, password);
        return of(map);
    }

    @Override
    public Optional<char[]> lookup(String secretName) {
        String value = passwords.get(secretName);
        return value == null ? Optional.empty() : Optional.of(value.toCharArray());
    }

    @Override
    public String toString() {
        return "FixedPasswordProvider{keys=" + passwords.keySet() + "}";
    }
}
