package com.example.tls.security;

import com.example.tls.exception.TlsConfigurationException;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordProviderTest {

    private static final String KEY = "password.provider.test.key";

    @Test
    void environmentProviderIsAbsentForUnknownVariables() {
        assertTrue(new EnvironmentPasswordProvider()
                .lookup("definitely.not.a.real.env.var." + System.nanoTime()).isEmpty());
    }

    @Test
    void systemPropertyProviderReadsJvmProperties() {
        System.setProperty(KEY, "secret-value");
        try {
            Optional<char[]> value = new SystemPropertyPasswordProvider().lookup(KEY);
            assertTrue(value.isPresent());
            assertArrayEquals("secret-value".toCharArray(), value.orElseThrow());
        } finally {
            System.clearProperty(KEY);
        }
    }

    @Test
    void compositeUsesFirstProviderInOrder() {
        System.setProperty(KEY, "from-system");
        try {
            PasswordProvider provider = CompositePasswordProvider.of(
                    new EnvironmentPasswordProvider(),
                    new SystemPropertyPasswordProvider());
            assertEquals("from-system", new String(provider.resolve(KEY)));
        } finally {
            System.clearProperty(KEY);
        }
    }

    @Test
    void fixedProviderIsDeterministicAndNeverLeaksValues() {
        PasswordProvider provider = FixedPasswordProvider.of("a", "123");
        assertEquals("123", new String(provider.resolve("a")));
        assertFalse(provider.toString().contains("123"));
    }

    @Test
    void missingSecretFailsFastWithClearError() {
        PasswordProvider provider = new EnvironmentPasswordProvider();
        TlsConfigurationException error =
                assertThrows(TlsConfigurationException.class, () -> provider.resolve(KEY));
        assertTrue(error.getMessage().contains(KEY));
    }
}
