package com.example.tls.server;

import com.example.tls.connection.TlsConnection;

/**
 * Application hook invoked once per established connection, always from a
 * bounded worker thread. Throwables are logged by the server and never kill the
 * accept loop or other connections.
 */
@FunctionalInterface
public interface TlsConnectionHandler {

    void handle(TlsConnection connection) throws Exception;
}
