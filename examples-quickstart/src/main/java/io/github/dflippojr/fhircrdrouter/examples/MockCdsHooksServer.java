package io.github.dflippojr.fhircrdrouter.examples;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;

/**
 * Stands in for a real payer's CDS Hooks endpoint so the quickstart example
 * can run end-to-end without needing an actual payer sandbox. Not part of
 * the library — example-only.
 *
 * <p>The response bodies live in {@code mock-payer/*.json} so CI's
 * {@code fhir-validator} job can check the FHIR resources inside them.
 */
final class MockCdsHooksServer {

    private final HttpServer server;

    MockCdsHooksServer(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", port), 0);

        byte[] discovery = body("cds-services.json");
        server.createContext("/cds-services", exchange -> respond(exchange, discovery));

        // A CRD 2.x-style response: an instructions card plus a coverage-information system action.
        byte[] priorAuthCheck = body("prior-auth-check.json");
        server.createContext("/cds-services/prior-auth-check", exchange -> respond(exchange, priorAuthCheck));
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

    private static byte[] body(String name) {
        try (InputStream in = MockCdsHooksServer.class.getResourceAsStream("/mock-payer/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing resource mock-payer/" + name);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, byte[] bytes) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (var os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
