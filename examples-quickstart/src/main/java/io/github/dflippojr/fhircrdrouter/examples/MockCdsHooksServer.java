package io.github.dflippojr.fhircrdrouter.examples;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 * Stands in for a real payer's CDS Hooks endpoint so the quickstart example
 * can run end-to-end without needing an actual payer sandbox. Not part of
 * the library — example-only.
 */
final class MockCdsHooksServer {

    private final HttpServer server;

    MockCdsHooksServer(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", port), 0);

        server.createContext("/cds-services", exchange -> respond(exchange, """
                {"services":[{"hook":"order-sign","title":"Prior Auth Check","description":"Checks prior auth requirements","id":"prior-auth-check"}]}"""));

        server.createContext("/cds-services/prior-auth-check", exchange -> respond(exchange, """
                {"cards":[{"summary":"Prior authorization required for this service","indicator":"warning","detail":"Contact DEMO-PAYER utilization management before proceeding."}]}"""));
    }

    void start() {
        server.start();
    }

    void stop() {
        server.stop(0);
    }

    int port() {
        return server.getAddress().getPort();
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (var os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
