package io.github.dflippojr.fhircrdrouter.client.testsupport;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * A loopback HTTP server standing in for a payer across many property-test tries: one server per
 * test container, with the response and the recorded requests reset for each try.
 */
public final class LoopbackPayer implements AutoCloseable {

    /** What the server received, with the path and query exactly as sent on the wire. */
    public record Received(String method, String rawPath, String rawQuery, String authorization, String body) { }

    /** A canned reply. */
    public record Reply(int status, String body) { }

    private final HttpServer server;
    private final List<Received> received = new CopyOnWriteArrayList<>();
    private volatile Function<Received, Reply> responder = r -> new Reply(200, "{}");

    public LoopbackPayer() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext("/", exchange -> {
            Received request = new Received(exchange.getRequestMethod(), exchange.getRequestURI().getRawPath(),
                    exchange.getRequestURI().getRawQuery(), exchange.getRequestHeaders().getFirst("Authorization"),
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            received.add(request);
            Reply reply = responder.apply(request);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            TestResponses.respond(exchange, reply.status(), reply.body());
        });
        server.start();
    }

    /** {@code http://127.0.0.1:<port>}, without a trailing slash. */
    public String origin() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** Clears the recorded requests and answers every request with {@code responder}. */
    public void reset(Function<Received, Reply> responder) {
        received.clear();
        this.responder = responder;
    }

    public List<Received> received() {
        return List.copyOf(received);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
