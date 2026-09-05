package com.example.tls.config;

/**
 * TLS endpoint role. Controls which keystore/truststore combination is required
 * and which Extended Key Usage must be present on the local certificate.
 */
public enum EndpointRole {

    // serverAuth OID 1.3.6.1.5.5.7.3.1
    SERVER("serverAuth", "1.3.6.1.5.5.7.3.1"),
    // clientAuth OID 1.3.6.1.5.5.7.3.2
    CLIENT("clientAuth", "1.3.6.1.5.5.7.3.2");

    private final String keyUsageDisplayName; // 人读名称：serverAuth / clientAuth
    private final String extendedKeyUsageOid; // RFC 5280 EKU OID，用于启动期证书校验

    EndpointRole(String keyUsageDisplayName, String extendedKeyUsageOid) {
        this.keyUsageDisplayName = keyUsageDisplayName;
        this.extendedKeyUsageOid = extendedKeyUsageOid;
    }

    /** Human readable EKU name, e.g. {@code serverAuth}. */
    public String keyUsageDisplayName() {
        return keyUsageDisplayName;
    }

    /** RFC 5280 Extended Key Usage OID expected for this role. */
    public String extendedKeyUsageOid() {
        return extendedKeyUsageOid;
    }
}
