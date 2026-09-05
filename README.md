# Production-Oriented TLS Foundation Demo (JDK 17 + JSSE)

这是一个 **TLS 基础设施 Demo**：只做 TLS 1.2 / TLS 1.3 的单向认证与双向认证（mTLS），并把
`TlsConfig → KeyManager/TrustManager → SSLContext → SSLSocket/SSLServerSocket` 的整条链路设计成
可以搬进真实项目继续演进的基础组件。它**不是**业务服务器，不实现 HTTP/RPC/服务发现/负载均衡/认证授权。

所有 TLS、证书链校验、密码学、握手与记录协议都交给 **JDK 17 自带 JSSE（SunJSSE）**；运行时没有引入
Spring/Netty/Tomcat/Jetty/Apache HttpClient/OkHttp/BouncyCastle 等任何第三方 TLS 或密码学框架。
唯一的第三方依赖是测试期的 JUnit 5。

---

## 1. 环境要求

| 工具 | 版本/说明 |
| --- | --- |
| JDK | **17**（本机如默认是其它版本，请显式设置 `JAVA_HOME`） |
| Maven | 3.8+，运行在 JDK 17 上 |
| OpenSSL | 1.1.1+ / 3.x / LibreSSL 3.x（测试用 LibreSSL 3.3.6 通过） |
| keytool | JDK 17 自带（证书脚本与测试均可用） |

macOS 示例：

```bash
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
export PATH="$JAVA_HOME/bin:$PATH"
java -version   # 应显示 17.x
mvn -version
```

## 2. 构建

```bash
mvn clean verify
```

`mvn verify` 会执行：

1. 编译主代码与测试代码；
2. 单元测试（配置、校验器、Cipher Suite 策略、密码提供器、证书工具、可观测性）；
3. 集成测试（真实监听 `SSLServerSocket` 并通过 `SSLSocket` 完成握手，测试期用 OpenSSL 在
   `target/generated-test-certs` 临时生成 CA/证书，不写入仓库）；
4. 打包可执行 JAR：`tls-demo/target/tls-demo-1.0.0.jar`。

> 集成测试需要允许程序绑定本地回环端口。如果你使用沙箱/容器，请给测试进程监听端口的权限。

## 3. 生成证书

### 3.1 OpenSSL 方案

```bash
./scripts/openssl/generate-all.sh
```

生成在 `certs/openssl/`：

| 文件 | 用途 |
| --- | --- |
| `ca.key`, `ca.crt` | Demo Root CA |
| `server.key`, `server.crt`, `server-chain.crt` | Server 私钥/证书/链 |
| `client.key`, `client.crt`, `client-chain.crt` | Client 私钥/证书/链 |
| `server.p12`, `client.p12` | PKCS12 身份库 |
| `server-truststore.p12` | Server 验证 Client 时信任的 CA |
| `client-truststore.p12` | Client 验证 Server 时信任的 CA |
| `*-keystore.password`, `*-truststore.password` | 本地演示密码文件（`chmod 600`） |

脚本按需执行顺序为 `generate-ca.sh` → `generate-server-cert.sh` → `generate-client-cert.sh`；
`clean.sh` 只删除上面列出的产物，不会触碰仓库其它内容。

### 3.2 keytool 方案

```bash
./scripts/keytool/generate-all.sh
```

生成在 `certs/keytool/`，结构与 OpenSSL 方案一致。默认使用 **PKCS12**：

- CA 流程：`-genkeypair`（CA 自签名）→ `-exportcert`；
- Server/Client 流程：`-genkeypair` 生成带 SAN/KU/EKU 的占位证书 → 导入 Root CA 作为信任锚 →
  `-certreq` 生成 CSR → `-gencert` 由 CA 签发 → `-importcert` 把证书回复装入原私钥条目（形成链）。

JKS 兼容：`KEYSTORE_TYPE=JKS ./scripts/keytool/generate-all.sh`。JKS 只应服务于必须兼容老配置的
迁移场景；新环境一律用 PKCS12。

### 3.3 证书扩展说明

脚本按以下要求生成证书：

| 扩展 | 示例 | 作用 |
| --- | --- | --- |
| Basic Constraints | CA:TRUE,pathlen:1 / CA:FALSE | 区分 CA 与叶子证书，阻止 CA 被当叶子用 |
| Key Usage | `keyCertSign,cRLSign` / `digitalSignature,keyEncipherment` | 声明密钥用途 |
| Extended Key Usage | `serverAuth` / `clientAuth` | Server 与 Client 证书分开用途 |
| Subject Alternative Name | `DNS:localhost,DNS:server,IP:127.0.0.1` | 主机身份标识（不是 CN） |
| Authority/Subject Key Identifier | `keyid,issuer` / `hash` | 链构建与调试 |

Java 启动时会 fail-fast 检查：本地证书是否过期、EKU 是否正确（server 证书含 `serverAuth`、
client 证书含 `clientAuth`）、KeyStore/TrustStore 是否存在且类型可用。证书 30 天内到期会输出警告，
已过期则拒绝启动。

### 3.4 连接抽象（核心不绑定行协议）

核心 `TlsConnection` 只暴露 `inputStream()/outputStream()`（传输层语义），不包含任何应用 framing；
Demo/测试使用的 UTF-8 行协议由 `LineTlsConnection` 这一可选 adapter 提供，且单行默认限制为
1 MiB。真实业务可以换成长度前缀、protobuf 或任意流协议，无需改动 TLS 核心。

## 4. KeyStore / TrustStore 语义

| 角色 | KeyStore（身份） | TrustStore（验证对端） |
| --- | --- | --- |
| TLS Server | 必须：Server 私钥 + Server 证书 + 链 | `NONE`：不需要；`WANT`/`NEED`：需要（`NEED` 为硬性要求） |
| TLS Client | 单向 TLS：不需要；mTLS：必须（Client 私钥+证书+链） | 必须：验证 Server 证书 |

验证动作（链构建、有效期、信任锚、Key Usage/EKU）全部由 JSSE 的 PKIX `TrustManager` 完成。
项目里**没有** trust-all `TrustManager`，**没有**绕过 hostname 校验的默认路径。

## 5. NONE / WANT / NEED

| 模式 | 语义 | 客户端无证书 | 客户端有被信任证书 |
| --- | --- | --- | --- |
| `NONE` | 服务端不请求客户端证书 | 成功，不认证 | 成功，但服务端不请求也不使用它 |
| `WANT` | 服务端请求证书但不强制 | 成功（不认证） | 成功并完成客户端认证 |
| `NEED` | 标准 mTLS，必须认证 | 握手失败 | 成功并完成客户端认证 |

映射到 JSSE：

- `NONE` → 不设置 `want/needClientAuth`；
- `WANT` → `SSLServerSocket.setWantClientAuth(true)`；
- `NEED` → `SSLServerSocket.setNeedClientAuth(true)`。

生产 mTLS 默认推荐 `NEED`。`WANT` 只能用于“可选认证”类场景，且配置了 TrustStore 时“出示证书但
不被信任”的连接仍会失败。

## 6. 运行 Demo

### 6.1 密码来源

密码**不写死在代码、配置或 Git**。脚本只生成 `*.password` 文件（权限 600），运行时通过
`TLS_KEYSTORE_PASSWORD` / `TLS_TRUSTSTORE_PASSWORD` 注入：

```bash
export TLS_KEYSTORE_PASSWORD="$(cat certs/openssl/server-keystore.password)"
export TLS_TRUSTSTORE_PASSWORD="$(cat certs/openssl/server-truststore.password)"
```

也支持 `-DTLS_KEYSTORE_PASSWORD=...` 系统属性。加载顺序：环境变量 → 系统属性。

**IDE / 本地直接运行（Demo 便捷模式）**：如果环境变量与系统属性都未配置，
Demo 启动器会自动读取 `certs/openssl/`（或 `certs/keytool/`）下脚本生成的对应
`server-keystore.password` / `server-truststore.password` / `client-keystore.password` /
`client-truststore.password` 文件。该回退只在 Demo 层实现，用于“IntelliJ 里直接点 Run”，
文件仍为 chmod 600 且被 .gitignore 覆盖；生产代码应始终使用 Secret Manager/KMS/Vault 注入。

### 6.2 一键 mTLS TLS 1.3 示例

推荐直接把下面的命令按顺序复制到两个终端运行。Demo 在未设置环境变量/系统属性时会自动读取
`certs/openssl/`（或 `certs/keytool/`）里脚本生成的密码文件，因此本地“开箱即可运行”；
需要显式注入密码时，按 6.1 的环境变量方式操作即可。

两个终端都要先执行的前提（必须位于项目根目录，因为 properties 里的证书路径是相对路径；
JAR 由 JDK 17 构建，默认 JDK 不是 17 时必须切换）：

```bash
cd /Users/hsinliao/work/workspace/tls-demo   # 换成你的项目根目录
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
export PATH="$JAVA_HOME/bin:$PATH"
java -version   # 应显示 17.x
```

终端 1（服务端）：

```bash
java -jar tls-demo/target/tls-demo-1.0.0.jar server \
  --config config-examples/mtls-tls13/server.properties \
  --host 127.0.0.1 --port 8443
```

终端 2（客户端）：

```bash
java -jar tls-demo/target/tls-demo-1.0.0.jar client \
  --config config-examples/mtls-tls13/client.properties \
  --host localhost --port 8443
```

`--host` / `--port` 都可以省略：服务端默认监听 `127.0.0.1:8443`，客户端默认连接
properties 中 `demo.peer.host` / `demo.peer.port` 指向的地址。

### 6.3 一键单向 TLS 1.3 示例

同样把 `config-examples/mtls-tls13/*.properties` 换成 `config-examples/oneway-tls13/*.properties`，
Server 只导出 keystore 密码，Client 只导出 truststore 密码即可。

### 6.4 开箱即改的 properties 示例目录

仓库已提供可直接修改路径/端口/协议使用的示例文件（每个组合都分开 `server/` 与 `client/`）：

| 组合 | Server 示例 | Client 示例 |
| --- | --- | --- |
| TLS1.2 + NONE | `config-examples/tls12-none/server.properties` | `config-examples/tls12-none/client.properties` |
| TLS1.2 + WANT（无客户端证书） | `config-examples/tls12-want/server.properties` | `config-examples/tls12-want/client.properties` |
| TLS1.2 + WANT（携带客户端证书） | 同上 | `config-examples/tls12-want/client-with-cert.properties` |
| TLS1.2 + NEED（mTLS） | `config-examples/tls12-need/server.properties` | `config-examples/tls12-need/client.properties` |
| TLS1.3 + NONE | `config-examples/tls13-none/server.properties` | `config-examples/tls13-none/client.properties` |
| TLS1.3 + WANT（无客户端证书） | `config-examples/tls13-want/server.properties` | `config-examples/tls13-want/client.properties` |
| TLS1.3 + WANT（携带客户端证书） | 同上 | `config-examples/tls13-want/client-with-cert.properties` |
| TLS1.3 + NEED（mTLS） | `config-examples/tls13-need/server.properties` | `config-examples/tls13-need/client.properties` |
| TLS1.2 + 显式 Cipher 白名单 | `config-examples/cipher-whitelist-tls12/server.properties` | `config-examples/cipher-whitelist-tls12/client.properties` |
| TLS1.3 + 显式 Cipher 白名单 | `config-examples/cipher-whitelist-tls13/server.properties` | `config-examples/cipher-whitelist-tls13/client.properties` |

例：运行 TLS1.2 + NEED（mTLS），终端 1 导出 Server 密码并启动：

```bash
export TLS_KEYSTORE_PASSWORD="$(cat certs/openssl/server-keystore.password)"
export TLS_TRUSTSTORE_PASSWORD="$(cat certs/openssl/server-truststore.password)"
java -jar tls-demo/target/tls-demo-1.0.0.jar server \
  --config config-examples/tls12-need/server.properties --port 8443
```

终端 2 导出 Client 密码并连接：

```bash
export TLS_KEYSTORE_PASSWORD="$(cat certs/openssl/client-keystore.password)"
export TLS_TRUSTSTORE_PASSWORD="$(cat certs/openssl/client-truststore.password)"
java -jar tls-demo/target/tls-demo-1.0.0.jar client \
  --config config-examples/tls12-need/client.properties --port 8443
```

只改证书路径/域名/端口时，直接编辑对应 properties 即可；密码永远不要写进文件。

### 6.5 六种组合的配置模板

把下面模板中需要改动的部分替换后即可覆盖 `TLS1.2/TLS1.3 × NONE/WANT/NEED`：

```properties
# server.properties
tls.name=my-server
tls.protocols=TLSv1.3            # 或 TLSv1.2，或 TLSv1.3,TLSv1.2
tls.cipherSuites=               # 空 = JDK 默认
tls.clientAuthentication.mode=NEED
tls.keyStore.type=PKCS12
tls.keyStore.path=certs/openssl/server.p12
tls.keyStore.passwordKey=TLS_KEYSTORE_PASSWORD
tls.trustStore.type=PKCS12      # NEED/WANT 需要；NONE 可不写
tls.trustStore.path=certs/openssl/server-truststore.p12
tls.trustStore.passwordKey=TLS_TRUSTSTORE_PASSWORD
tls.hostnameVerification.enabled=true
tls.connectTimeoutMillis=5000
tls.handshakeTimeoutMillis=10000
tls.socketTimeoutMillis=30000
```

```properties
# client.properties（mTLS 时同时有 keyStore 与 trustStore）
tls.name=my-client
tls.protocols=TLSv1.3
tls.cipherSuites=
tls.clientAuthentication.mode=NONE   # client 角色下该字段不生效，语义属 server 端
tls.keyStore.type=PKCS12
tls.keyStore.path=certs/openssl/client.p12
tls.keyStore.passwordKey=TLS_KEYSTORE_PASSWORD
tls.trustStore.type=PKCS12
tls.trustStore.path=certs/openssl/client-truststore.p12
tls.trustStore.passwordKey=TLS_TRUSTSTORE_PASSWORD
tls.hostnameVerification.enabled=true
tls.connectTimeoutMillis=5000
tls.handshakeTimeoutMillis=10000
tls.socketTimeoutMillis=30000
demo.peer.host=localhost
demo.peer.port=8443
```

六种组合：

| 组合 | server 关键差异 | client 关键差异 |
| --- | --- | --- |
| TLS1.2 + NONE | `protocols=TLSv1.2`, `mode=NONE` | 只有 trustStore |
| TLS1.2 + WANT | `protocols=TLSv1.2`, `mode=WANT` + trustStore | 有/无 keyStore 均可 |
| TLS1.2 + NEED | `protocols=TLSv1.2`, `mode=NEED` + trustStore | keyStore + trustStore |
| TLS1.3 + NONE | `protocols=TLSv1.3`, `mode=NONE` | 只有 trustStore |
| TLS1.3 + WANT | `protocols=TLSv1.3`, `mode=WANT` + trustStore | 有/无 keyStore 均可 |
| TLS1.3 + NEED | `protocols=TLSv1.3`, `mode=NEED` + trustStore | keyStore + trustStore |

### 6.6 预期输出

Server 启动打印脱敏 Effective Configuration，客户端握手后打印类似：

```text
TLS connection established

Protocol: TLSv1.3
Cipher Suite: TLS_AES_256_GCM_SHA384
Client certificate presented: true

Peer:
  Subject: CN=server
  Issuer:  CN=Demo Root CA

Handshake: SUCCESS
```

不会打印私钥、密码、密钥材料。

## 7. Cipher Suite 策略

**未配置（`cipherSuites=` 或空数组）**

不自己维护列表。`JsseCapabilities.probe()` 从 `SSLContext.getDefaultSSLParameters()` 读取当前
JDK Provider 的默认启用套件（该集合已受 `jdk.tls.disabledAlgorithms` 等安全策略约束），并保持
`SSLParameters` 的 cipher suites 为默认，不显式覆盖。JDK 升级后自动继承新的安全默认值。

> 注意：JDK 17 的“默认启用集”是为了兼容性而非“企业最严安全基线”，其中可能包含 CBC 或静态 RSA
> 套件（如 `TLS_RSA_WITH_AES_128_CBC_SHA`）。因此生产环境建议显式配置只含 ECDHE/AEAD 的白名单，
> 默认策略适合需要自动跟随 JVM 策略的场景。

**显式配置 = 严格白名单**

```properties
tls.cipherSuites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384
```

- 只允许列表内的套件；不自动补、不 fallback、不忽略、不静默改配置；
- 不支持的套件 → 启动失败：`Configured cipher suite '...' is not supported ...`；
- 含 `NULL/aNULL/EXPORT/RC4/DES/3DES/MD5/ANON` 的套件 → 安全策略拒绝；
- 套件与协议不兼容 → 启动失败：
  - TLS 1.3 只接受 RFC 8446 的 `TLS_AES_*` / `TLS_CHACHA20_POLY1305_SHA256`；
  - 只配置 `TLSv1.2` 时不能配置 TLS 1.3-only 套件；
  - 只配置 `TLSv1.3` 时不能配置 TLS 1.2 套件。

## 8. Protocol 策略与禁止降级

只允许显式 `TLSv1.2` / `TLSv1.3`：

```properties
tls.protocols=TLSv1.3,TLSv1.2
```

协议列表始终被显式写入 `SSLParameters`。服务端只允许 TLSv1.3、客户端只允许 TLSv1.2 时握手必然失败，
不会自动降级。配置 TLSv1.1/SSLv3/TLSv1 会直接 fail-fast。

## 9. Hostname Verification 与 SNI

- Client 通过 `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` 做 RFC 6125 端点识别，
  验证 SAN；
- 证书身份以 **SAN 为准**，CN 不再作为主机名身份来源；
- 默认禁止关闭。配置文件里显式 `tls.hostnameVerification.enabled=false` 会输出警告，仅允许受控测试；
- `TlsClient.connect(host, port)` 把主机名交给 `SSLSocketFactory.createSocket(plain, host, ...)`，
  JSSE 自动发送 SNI；测试还提供 `connectTo(peerHost, address)` 用于“身份主机名与实际地址分离”的负向测试。

## 10. ALPN / Session Resumption / 0-RTT

- `TlsConfig.applicationProtocols` 与 `SSLParameters.setApplicationProtocols(...)` 已预留，
  握手后可读 `SSLSession.getApplicationProtocol()`；
- 不做 HTTP/2，也**不主动实现 TLS 1.3 0-RTT**。0-RTT 涉及重放、幂等和应用语义，生产启用前必须
  单独评审；
- JDK 默认的 Session Resumption 保持由 JSSE 正常处理。

## 11. 证书轮换与 SSLContext Reload

核心设计：

```text
Existing connections  ──► 继续使用原有 TLS session/context
New connections       ──► 使用 reload 后的新 SSLContext
```

`DefaultTlsContextProvider` 持有 `AtomicReference<TlsContext>`。reload 流程：

1. 读取新配置/证书，构建并校验新 `TlsContext`；
2. 只有成功后才 `AtomicReference.set(...)`；
3. 失败时旧 context 保持 active，不切换到不可用状态。

`TlsServer.reloadTlsContext()` 会额外重建监听 socket，使**新连接**确实走新 SSLContext；已有连接不受影响。
Demo 中可把相同路径下的 `server.p12` 替换成新证书后调用 reload。实际生产一般配合 LB/发布窗口实现零感知，
或运行两个实例交错发布。

### 推荐 CA 轮换流程

1. 把新 Root CA（v2）加入 TrustStore（v1 与 v2 并存过渡）；
2. 用 v2 签发新 Server/Client 证书并发布；
3. 新连接使用新证书，旧连接继续走完过渡期；
4. 监控旧证书流量归零；
5. 从 TrustStore 移除旧 CA v1 并发布。

## 12. Secret 管理

代码层面：

- 配置中只出现**密码的符号名**（如 `TLS_KEYSTORE_PASSWORD`）；
- `PasswordProvider.lookup(String)` 在运行时解析真实值；
- 密码不进入 `TlsConfig`、日志、异常、Git；
- 内置 `EnvironmentPasswordProvider` / `SystemPropertyPasswordProvider` /
  `CompositePasswordProvider`；`FixedPasswordProvider` 仅测试用。

Demo 脚本为方便本地生成随机密码文件并 `chmod 600`，但它们只用于本地演示。生产环境建议：

- Kubernetes Secret / Mounted Secret；
- Secret Manager / Vault / AWS Secrets Manager；
- KMS 解密后的短生命周期 Secret；
- HSM / PKCS#11 私钥托管。

## 13. 超时与并发/生命周期

三个超时分开配置：

| 字段 | 默认 | 作用 |
| --- | --- | --- |
| `connectTimeout` | 5000ms | TCP connect（Client） |
| `handshakeTimeout` | 10000ms | `startHandshake()` 前设置 `SO_TIMEOUT` |
| `socketTimeout` | 30000ms | 握手成功后恢复的读超时 |

服务端：

- acceptor 单线程 `accept()`；
- 连接处理放进**有界线程池 + 有界队列**，不会无限创建线程；
- `stop()` 先停止 accept，再 `shutdown()` 工作线程池，等待 `shutdownGracePeriod` 后强制关闭仍在运行的连接；
- 客户端与连接均支持 try-with-resources；关闭 Socket/Stream/线程池，处理中断。

## 14. 可观测性

`TlsHandshakeObserver` 可以观察：

- 握手开始/成功/失败；
- protocol、cipher suite；
- peer certificate subject / issuer；
- 是否出现对端证书、ALPN 结果；
- 连接地址（无密钥/密码）。

`TlsMetrics` 提供线程安全的成功/失败计数与按 protocol/cipher 的分布快照；
`LoggingTlsHandshakeObserver` 只记录脱敏字段。

Server/Client 启动时打印 Effective Configuration（协议、cipher 策略、clientAuth、store 类型/路径、
hostname verification、timeout、context id）。绝不打印密码和私钥。

## 15. TLS Debug（仅排障）

```bash
java -Djavax.net.debug=ssl,handshake -jar tls-demo/target/tls-demo-1.0.0.jar client --config ...
```

- 默认关闭；
- 输出非常详细且可能包含敏感握手上下文，只允许 troubleshooting；
- 生产环境慎开，配合脱敏日志采集。

## 16. 异常体系

```text
TlsException
├── TlsConfigurationException   配置/策略错误，fail-fast
├── TlsCertificateException     证书加载、过期、EKU、store 内容错误
├── TlsInitializationException  SSLContext / 端点初始化失败
├── TlsHandshakeException       握手/认证/协议失败
└── TlsConnectionException      TCP/TLS I/O 错误
```

异常消息包含可读上下文、不含密码/私钥；代码不吞异常、不用 `printStackTrace` 代替日志。

## 17. Docker / Kubernetes（生产建议）

项目不包含默认镜像配置（演示不依赖容器）。生产部署建议：

- 用 `Dockerfile` 固定 JDK 17 基础镜像并只复制 `tls-demo/target/tls-demo-1.0.0.jar` 与只读配置；
- Secret 以 **Kubernetes Secret/Mounted Secret** 注入，密码通过环境变量传给应用；
- p12/jks/key 永不进入镜像层或 Git；可每次启动从 Secret Manager/KMS 拉取后写入 `emptyDir` 或 tmpfs；
- 证书轮换配合 `reloadTlsContext`、探针与发布窗口；
- 多实例部署在 LB 之后；容器内进程以非 root 运行，最小化 capabilities；
- 镜像扫描与依赖审计在 CI 中执行。

## 18. FIPS / HSM / PKCS#11 扩展边界

当前版本不实现 FIPS/HSM/PKCS#11，但接口不阻塞未来扩展：

- `StoreConfig` 同时支持文件来源与 Provider 来源：`StoreConfig.provider("PKCS11", providerName, pinKey)`
  无需文件路径；loader 对 Provider store 走 `KeyStore.load(null, tokenPin)`；
- 私钥不设计成 `String` 传递，也没有“必须明文私钥落盘”的核心接口；
- `TlsContextFactory` 使用 `KeyManagerFactory`/`TrustManagerFactory`，可切换到
  `SunPKCS11` 或企业 FIPS provider，不修改上层 `TlsClient/TlsServer`。

properties 形态（HSM/PKCS#11，无 path）：

```properties
tls.keyStore.type=PKCS11
tls.keyStore.providerName=SunPKCS11-HSM
tls.keyStore.passwordKey=TLS_HSM_PIN
# 注意：不要配置 tls.keyStore.path
```

## 19. 常见错误排查

| 现象 | 原因/处理 |
| --- | --- |
| `PKIX path building failed` | Client/Server 未信任签发对端证书的 CA：检查 TrustStore 与 CA 轮换步骤 |
| `handshake_failure` | 协议集合无交集、无共同 cipher、密钥/证书算法不匹配 |
| `certificate_unknown` | 对端证书不受信任或链不完整 |
| `bad_certificate` | 证书被拒（EKU、过期、链问题） |
| `No available authentication scheme` | Server 需要但 Client 没有可用的私钥/证书 |
| `certificate_required` | `NEED` 下客户端没有提供证书 |
| Hostname verification failed | 访问主机名不在服务器证书 SAN 中；SAN 才是身份 |
| `Unsupported cipher suite ...` | 白名单含当前 JVM 不支持的套件：fail-fast，检查 JDK/Provider |
| 密码错误/`keystore password was incorrect` | 检查对应 `TLS_KEYSTORE_PASSWORD`/`TLS_TRUSTSTORE_PASSWORD` |
| 测试不能绑定端口 | 沙箱/容器需允许 loopback listen |

## 20. 测试矩阵

### 单元测试

- `TlsConfigTest`：不可变配置、防御性拷贝、默认值；
- `TlsConfigValidatorTest`：空/旧协议、零超时、角色结构、过期证书；
- `TlsCipherSuitePolicyTest`：默认 vs 白名单、不支持、不安全关键字、协议不兼容；
- `PasswordProviderTest`：env/system property/composite/fixed、缺失 fail-fast；
- `CertificateUtilsTest`：过期检测、EKU；
- `JsseCapabilitiesTest`、`TlsMetricsTest`。

### 集成测试（真实握手）

| 维度 | 组合 | 预期 |
| --- | --- | --- |
| TLS1.2 × NONE | 无客户端证书 | 成功，server-auth=false |
| TLS1.2 × WANT | 有客户端证书 | 成功，server-auth=true |
| TLS1.2 × WANT | 无客户端证书 | 成功，server-auth=false |
| TLS1.2 × NEED | 有信任的客户端证书 | 成功，server-auth=true |
| TLS1.3 × NONE | 无客户端证书 | 成功，server-auth=false |
| TLS1.3 × WANT | 有/无客户端证书 | 成功（认证与否取决于是否出示证书） |
| TLS1.3 × NEED | 有信任的客户端证书 | 成功 |
| NONE | 客户端带证书 | 成功且不被服务端要求/使用 |
| NEED | 客户端无证书 | 握手失败 |
| NEED | 客户端证书不被 Server TrustStore 信任 | 握手失败 |
| Hostname | SAN ≠ 请求主机名 | 握手失败（未关闭 hostname verification） |
| Protocol | Server TLS1.3-only vs Client TLS1.2-only | 握手失败（不降级） |
| Cipher default | 未配置 | 协商结果来自 JDK 默认启用集 |
| Cipher whitelist | TLS1.3 `TLS_AES_256_GCM_SHA384` | 只协商该套件 |
| Cipher whitelist | TLS1.2 `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 只协商该套件 |
| Reload | reload 成功后新连接 | 新连接使用新 context |
| Reload | reload 期间旧连接 | 旧连接继续使用原 session |
| Reload | reload 失败 | 旧 SSLContext 仍 active |
| 证书校验 | 过期 server 证书 | 启动失败（fail-fast） |

## 21. 目录结构

```text
tls-demo/
├── pom.xml
├── README.md
├── .gitignore
├── certs/
│   └── .gitkeep                 # 证书/密码只在此目录生成，已被 gitignore
├── config-examples/
│   ├── tls12-none|want|need/     # TLS1.2 × NONE/WANT/NEED
│   ├── tls13-none|want|need/     # TLS1.3 × NONE/WANT/NEED
│   ├── cipher-whitelist-tls12|tls13/
│   └── oneway-tls13|mtls-tls13/  # 旧别名，仍可使用
├── scripts/
│   ├── openssl/                 # CA/server/client 一键脚本
│   └── keytool/                 # keytool 等价脚本（默认 PKCS12，可 JKS）
├── tls-core/                     # 可复用 TLS 基础库（可发布为独立 artifact）
│   ├── pom.xml
│   └── src/{main,test}/java/com/example/tls/
│       ├── certificate/ client/ config/ connection/ context/
│       ├── exception/ observability/ security/ server/ validation/
│       └── testing/ integration/ ...（单元/集成测试）
└── tls-demo/                     # Demo 应用层（依赖 tls-core，不允许反向依赖）
    ├── pom.xml
    └── src/main/java/com/example/tls/demo/  # CLI/Properties/Echo
```

### 为什么拆成两个模块？

- `tls-core`：不含任何应用协议或本地便利实现，可以在 reactor 内直接跑全部单元/集成测试，也可
  `mvn install` 后作为 artifact 发布给其它服务复用；
- `tls-demo`：只依赖 `tls-core`，包含 CLI、properties 加载、行协议 Echo 与本地密码文件回退；
- 编译器强制了依赖方向：Demo 引用 Core 合法，Core 反向引用 Demo 无法编译；
- 仓库根目录执行 `mvn clean verify` 会依次构建 core → demo，集成测试仍真实完成 TLS 握手。

## 22. Final Review

- ✅ JDK 17 compatible（全部 API 在 JDK 17 JSSE 中存在并实测）
- ✅ TLS 1.2 / TLS 1.3
- ✅ 单向 TLS / 双向 TLS（mTLS）
- ✅ `NONE` / `WANT` / `NEED`
- ✅ cipher 未配置 → JDK 默认；显式 → 严格白名单；非法/不兼容 fail-fast
- ✅ 无 trust-all、无 hostname bypass、无自动降级、无硬编码密码
- ✅ CA/Server/Client 证书链、SAN、KU、EKU 正确配置
- ✅ OpenSSL 与 keytool 两套脚本
- ✅ 证书轮换与 SSLContext reload（新连接新 context，旧连接不受影响）
- ✅ 过期证书 fail-fast，30 天内警告
- ✅ 单元测试 + 真实握手集成测试 + 负向测试
