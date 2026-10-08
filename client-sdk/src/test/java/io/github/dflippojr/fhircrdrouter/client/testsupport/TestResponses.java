package io.github.dflippojr.fhircrdrouter.client.testsupport;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Writes the UTF-8 text response bodies shared by the loopback HTTP(S) test servers. */
public final class TestResponses {

    private TestResponses() {
    }

    /** Sends {@code status} with {@code body} as UTF-8; the caller sets any headers first. */
    public static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (var out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
