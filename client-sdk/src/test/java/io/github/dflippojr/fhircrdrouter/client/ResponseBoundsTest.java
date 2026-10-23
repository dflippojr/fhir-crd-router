package io.github.dflippojr.fhircrdrouter.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A payer cannot hold a call open past the request timeout, or make the client buffer an unbounded body. */
class ResponseBoundsTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(1);

    private HttpServer server;
    private ConnectionRecord record;
    private final List<PayerExchange> exchanges = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
        record = ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort())
                .authType(AuthType.NONE).build();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void bodyThatTricklesPastTheRequestTimeoutTimesOut() {
        server.createContext("/cds-services", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                for (int i = 0; i < 40; i++) {
                    out.write(' ');
                    out.flush();
                    Thread.sleep(100);
                }
                out.write("{\"services\":[]}".getBytes(StandardCharsets.UTF_8));
            } catch (IOException | InterruptedException e) {
                // The client gave up; that is the point.
            }
        });

        long started = System.nanoTime();
        PayerCallException error = assertThrows(PayerCallException.class, () -> client().discoverServices(record));
        Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

        assertTrue(error.timedOut(), "a body still arriving at the deadline is a timeout");
        assertEquals(PayerCallPhase.DISCOVERY, error.phase());
        assertTrue(elapsed.compareTo(Duration.ofMillis(3500)) < 0, "gave up after " + elapsed);
        assertEquals(1, exchanges.size());
        assertNotNull(exchanges.get(0).error());
    }

    @Test
    void bodyLargerThanTheLimitFailsWithoutBufferingIt() throws Exception {
        // A client that buffers everything reads all of it; one that stops at the limit hangs up first.
        CompletableFuture<Boolean> hungUp = new CompletableFuture<>();
        server.createContext("/cds-services",
                exchange -> hungUp.complete(stream(exchange, 4L * CdsHooksClient.MAX_RESPONSE_BYTES)));

        PayerCallException error = assertThrows(PayerCallException.class,
                () -> client(Duration.ofSeconds(10)).discoverServices(record));

        assertFalse(error.timedOut());
        assertTrue(error.statusCode().isEmpty());
        assertEquals(PayerCallPhase.DISCOVERY, error.phase());
        assertEquals(1, exchanges.size());
        assertNotNull(exchanges.get(0).error());
        assertTrue(hungUp.get(5, TimeUnit.SECONDS), "the client read the whole body before failing");
    }

    @Test
    void bodyOfExactlyTheLimitIsAccepted() {
        server.createContext("/cds-services", exchange -> stream(exchange, CdsHooksClient.MAX_RESPONSE_BYTES));

        assertEquals(List.of(), client(Duration.ofSeconds(10)).discoverServices(record));
    }

    @Test
    void tokenResponsesAreBoundedToo() {
        ConnectionRecord oauth = ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl(record.baseUrl()).authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint(record.baseUrl() + "/token").clientId("c").credentialRef("ref").build();
        server.createContext("/token", exchange -> stream(exchange, CdsHooksClient.MAX_RESPONSE_BYTES + 1));

        PayerCallException error = assertThrows(PayerCallException.class,
                () -> new CdsHooksClient(HttpClient.newHttpClient(), secret())
                        .discoverServices(oauth));

        assertEquals(PayerCallPhase.TOKEN, error.phase());
    }

    @Test
    void bodyIsDecodedWithTheDeclaredCharset() {
        respondWith("application/json; charset=\"ISO-8859-1\"", StandardCharsets.ISO_8859_1);

        assertEquals("café", client().discoverServicesRaw(record).path("name").textValue());
    }

    @Test
    void charsetInsideAQuotedParameterIsIgnored() {
        respondWith("application/json; note=\"a; charset=ISO-8859-1\"; charset=UTF-8", StandardCharsets.UTF_8);

        assertEquals("café", client().discoverServicesRaw(record).path("name").textValue());
    }

    @Test
    void unknownOrMissingCharsetFallsBackToUtf8() {
        respondWith("application/json; charset=no-such-charset", StandardCharsets.UTF_8);
        assertEquals("café", client().discoverServicesRaw(record).path("name").textValue());

        server.removeContext("/cds-services");
        respondWith(null, StandardCharsets.UTF_8);
        assertEquals("café", client().discoverServicesRaw(record).path("name").textValue());
    }

    private void respondWith(String contentType, Charset charset) {
        server.createContext("/cds-services", exchange -> {
            byte[] body = "{\"services\":[],\"name\":\"café\"}".getBytes(charset);
            if (contentType != null) {
                exchange.getResponseHeaders().set("Content-Type", contentType);
            }
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
    }

    /**
     * Streams {@code {"services":[]}} padded with leading spaces to {@code size} bytes, without a length.
     * Returns true when the client hung up before the end.
     */
    private static boolean stream(HttpExchange exchange, long size) throws IOException {
        byte[] json = "{\"services\":[]}".getBytes(StandardCharsets.UTF_8);
        byte[] padding = new byte[64 * 1024];
        Arrays.fill(padding, (byte) ' ');
        exchange.sendResponseHeaders(200, 0);
        try (OutputStream out = exchange.getResponseBody()) {
            long remaining = size - json.length;
            while (remaining > 0) {
                int n = (int) Math.min(padding.length, remaining);
                out.write(padding, 0, n);
                remaining -= n;
            }
            out.write(json);
        } catch (IOException e) {
            return true;
        }
        return false;
    }

    private static CredentialProvider secret() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.of("secret"); }
            @Override public void put(String credentialRef, String secretValue) { throw new UnsupportedOperationException(); }
            @Override public void remove(String credentialRef) { throw new UnsupportedOperationException(); }
        };
    }

    private CdsHooksClient client() {
        return client(TIMEOUT);
    }

    private CdsHooksClient client(Duration timeout) {
        return new CdsHooksClient(HttpClient.newHttpClient(), null, null, timeout, timeout, exchanges::add);
    }
}
