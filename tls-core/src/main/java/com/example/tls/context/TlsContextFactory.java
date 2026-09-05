package com.example.tls.context;

import com.example.tls.config.ClientAuthMode;
import com.example.tls.config.EndpointRole;
import com.example.tls.config.TlsConfig;
import com.example.tls.exception.TlsInitializationException;
import com.example.tls.security.PasswordProvider;
import com.example.tls.validation.CipherSuitePlan;
import com.example.tls.validation.TlsCipherSuitePolicy;
import com.example.tls.validation.TlsConfigValidator;
import com.example.tls.validation.ValidatedStores;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.SecureRandom;

/**
 * Creates an instance-isolated {@link SSLContext} from a {@link TlsConfig}.
 * No JVM-global {@code javax.net.ssl.*} system properties are used.
 */
public final class TlsContextFactory {

    private TlsContextFactory() {
    }

    public static TlsContext create(TlsConfig config, EndpointRole role, PasswordProvider passwords) {
        // 先用真实 JVM capabilities 做协议/套件/角色/证书的全量校验，
        // 再初始化 SSLContext；任一步失败都抛 typed exception，不产生半成品。
        JsseCapabilities capabilities = JsseCapabilities.probe();
        // 校验与加载只做一次：返回的 KeyStore 直接复用于 KMF/TMF，
        // 避免 reload/启动时重复读盘与重复取口令。
        ValidatedStores stores = TlsConfigValidator.validate(config, role, passwords, capabilities);

        try {
            // 每个调用都创建独立 SSLContext，保证实例级隔离：
            // 同一 JVM 中多个 Server/Client 可持有完全不同的证书与信任锚。
            SSLContext sslContext = SSLContext.getInstance("TLS");
            KeyManager[] keyManagers = buildKeyManagers(config, passwords, stores.identityStore());
            TrustManager[] trustManagers = buildTrustManagers(config, role, stores.trustStore());
            sslContext.init(keyManagers, trustManagers, new SecureRandom());

            CipherSuitePlan plan =
                    TlsCipherSuitePolicy.resolve(config.protocols(), config.cipherSuites(), capabilities);
            return new TlsContext(sslContext, config, role, config.protocols(), plan);
        } catch (Exception e) {
            if (e instanceof com.example.tls.exception.TlsException tlsException) {
                throw tlsException;
            }
            throw new TlsInitializationException(
                    "Failed to initialize TLS context for '" + config.name() + "'", e);
        }
    }

    private static KeyManager[] buildKeyManagers(TlsConfig config,
                                                 PasswordProvider passwords, KeyStore store) {
        if (store == null) {
            return null;
        }
        try {
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            // 文件 store：条目口令可能独立于 store 口令；
            // Provider/HSM：私钥驻留 token，KMF 不再二次输入 PIN。
            char[] keyPassword = config.keyStore().isProviderBased()
                    ? null
                    : passwords.resolve(config.keyStore().effectiveKeyPasswordKey());
            // KMF.init(store, keyPassword) 是 JSSE 在握手时按 alias 取私钥的口令入口；
            // 这里只传符号名解析结果，密码不进 TlsConfig/日志。
            factory.init(store, keyPassword);
            return factory.getKeyManagers();
        } catch (Exception e) {
            if (e instanceof com.example.tls.exception.TlsException tlsException) {
                throw tlsException;
            }
            throw new TlsInitializationException(
                    "Unable to build key managers for '" + config.name() + "'", e);
        }
    }

    private static TrustManager[] buildTrustManagers(TlsConfig config, EndpointRole role,
                                                     KeyStore anchors) {
        try {
            if (anchors == null && role == EndpointRole.SERVER
                    && config.clientAuthentication().mode() != ClientAuthMode.NONE) {
                // 关键安全边界：WANT 未配置 TrustStore 时，不能把 TrustManager 置 null
                // （那会静默使用 JVM 全局默认 cacerts）。改为显式空信任锚库：
                // 出示证书的客户端必然被拒，匿名客户端仍可按 WANT 语义连接。
                anchors = KeyStore.getInstance(KeyStore.getDefaultType());
                anchors.load(null, null);
            }
            if (anchors == null) {
                return null;
            }

            TrustManagerFactory factory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(anchors);
            return factory.getTrustManagers();
        } catch (Exception e) {
            if (e instanceof com.example.tls.exception.TlsException tlsException) {
                throw tlsException;
            }
            throw new TlsInitializationException(
                    "Unable to build trust managers for '" + config.name() + "'", e);
        }
    }
}
