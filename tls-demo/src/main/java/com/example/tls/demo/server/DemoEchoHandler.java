package com.example.tls.demo.server;

import com.example.tls.connection.TlsConnection;
import com.example.tls.connection.LineTlsConnection;
import com.example.tls.observability.HandshakeInfo;
import com.example.tls.server.TlsConnectionHandler;

import java.util.Optional;

/**
 * Demo application handler. It first reports the server-side handshake
 * observation, then echoes every received line. This is intentionally simple
 * application logic; all TLS behavior stays in the core layer.
 */
public final class DemoEchoHandler implements TlsConnectionHandler {

    @Override
    public void handle(TlsConnection connection) throws Exception {
        // 行 framing 是 demo 协议，放在这里而不侵入核心 TlsConnection。
        try (LineTlsConnection lines = LineTlsConnection.wrap(connection)) {
            HandshakeInfo info = lines.handshakeInfo();
            lines.sendLine("server-auth=" + info.peerCertificatesPresent()
                    + " protocol=" + info.protocol()
                    + " cipher=" + info.cipherSuite());

            Optional<String> line;
            while ((line = lines.receiveLine()).isPresent()) {
                String message = line.get();
                if ("bye".equalsIgnoreCase(message.trim())) {
                    lines.sendLine("bye");
                    break;
                }
                lines.sendLine("echo:" + message);
            }
        }
    }
}
