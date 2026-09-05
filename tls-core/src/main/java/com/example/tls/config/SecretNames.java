package com.example.tls.config;

/**
 * Well-known symbolic secret names used by the demo. Real applications should
 * feed these names from their own secret-management layer (Secret Manager,
 * Kubernetes Secret, Vault, KMS, HSM, ...).
 */
public final class SecretNames {

    /** Environment/system-property name conventionally used for the key store password. */
    public static final String TLS_KEYSTORE_PASSWORD = "TLS_KEYSTORE_PASSWORD";

    /** Environment/system-property name conventionally used for the trust store password. */
    public static final String TLS_TRUSTSTORE_PASSWORD = "TLS_TRUSTSTORE_PASSWORD";

    /** Short alias kept for API ergonomics. */
    public static final String KEYSTORE_PASSWORD = TLS_KEYSTORE_PASSWORD;

    /** Short alias kept for API ergonomics. */
    public static final String TRUSTSTORE_PASSWORD = TLS_TRUSTSTORE_PASSWORD;

    private SecretNames() {
    }
}
