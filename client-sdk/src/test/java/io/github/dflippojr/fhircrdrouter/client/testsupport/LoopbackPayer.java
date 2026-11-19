package io.github.dflippojr.fhircrdrouter.client.testsupport;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * The fake payer for client tests: a loopback HTTP server with canned replies and recorded requests.
 *
 * <p>Every request is recorded before it is answered, so a responder may block (on a latch, say) and
 * the test still sees the request. Requests are served on a thread pool, so concurrent callers do not
 * queue behind a blocked responder.
 *
 * <p>Routing uses the JDK server's own contexts: {@link #on(String, Function)} registers a path, and
 * the longest registered prefix of the request path wins, exactly as {@code createContext} does in a
 * hand-rolled server. A request no route matches goes to the fallback, which answers {@code 200 {}}
 * until {@link #otherwise(Function)} or {@link #reset(Function)} changes it.
 *
 * <p>A responder that throws, or a scripted sequence that runs out, drops that connection (as a
 * throwing handler does in the JDK server) and is recorded; the next {@link #reset(Function)} or
 * {@link #close()} then fails the test with it, so a check inside a responder cannot fail silently,
 * even in a property-test try whose client expected the call to fail.
 *
 * <p>Tests with deliberate transport behaviour (slow or oversized bodies, dropped connections, TLS)
 * keep their own server.
 */
public final class LoopbackPayer implements AutoCloseable {

    /**
     * What the server received, with the path and query exactly as sent on the wire. {@code headers}
     * is looked up case-insensitively.
     */
    public record Received(String method, String rawPath, String rawQuery, Map<String, List<String>> headers,
                           String body) {
        public Received {
            Map<String, List<String>> copy = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            headers.forEach((name, values) -> copy.put(name, List.copyOf(values)));
            headers = Collections.unmodifiableMap(copy);
        }

        /** The first value of header {@code name}, or {@code null} when it was not sent. */
        public String header(String name) {
            List<String> values = headers.get(name);
            return values == null || values.isEmpty() ? null : values.get(0);
        }

        /** The {@code Authorization} header, or {@code null} when it was not sent. */
        public String authorization() {
            return header("Authorization");
        }
    }

    /**
     * A canned reply. A {@code null} body sends no body at all (length {@code -1}); any other body is
     * sent as UTF-8 with {@link TestResponses#respond}, so an empty body goes out chunked, as it does
     * from a hand-rolled server. Header names keep their order and repeated values are all sent.
     */
    public record Reply(int status, String body, Map<String, List<String>> headers) {
        public Reply {
            Map<String, List<String>> copy = new LinkedHashMap<>();
            headers.forEach((name, values) -> copy.put(name, List.copyOf(values)));
            headers = Collections.unmodifiableMap(copy);
        }

        /** {@code body} with {@code Content-Type: application/json}. */
        public Reply(int status, String body) {
            this(status, body, Map.of("Content-Type", List.of("application/json")));
        }

        /** {@code status} with no body and no headers, as for a 204, a bare 500 or a redirect. */
        public static Reply empty(int status) {
            return new Reply(status, null, Map.of());
        }

        /** This reply with {@code value} added to header {@code name}. */
        public Reply withHeader(String name, String value) {
            Map<String, List<String>> next = new LinkedHashMap<>(headers);
            List<String> values = new ArrayList<>(next.getOrDefault(name, List.of()));
            values.add(value);
            next.put(name, values);
            return new Reply(status, body, next);
        }

        /** This reply without header {@code name}, for example to send a body with no Content-Type. */
        public Reply withoutHeader(String name) {
            Map<String, List<String>> next = new LinkedHashMap<>(headers);
            next.remove(name);
            return new Reply(status, body, next);
        }
    }

    private final HttpServer server;
    private final ExecutorService threads = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "loopback-payer");
        thread.setDaemon(true);
        return thread;
    });
    private final List<Received> received = new CopyOnWriteArrayList<>();
    private final List<Throwable> failures = new CopyOnWriteArrayList<>();
    private final Set<String> routes = ConcurrentHashMap.newKeySet();
    private volatile Function<Received, Reply> fallback = r -> new Reply(200, "{}");

    public LoopbackPayer() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.setExecutor(threads);
        server.createContext("/", handler(request -> fallback.apply(request)));
        server.start();
    }

    /** {@code http://127.0.0.1:<port>}, without a trailing slash. */
    public String origin() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** {@link #origin()} followed by {@code path}, which starts with {@code /}. */
    public String url(String path) {
        return origin() + path;
    }

    /**
     * Answers requests under {@code path} with {@code responder}, replacing any earlier route for the
     * same path. Use {@link #otherwise(Function)} for {@code /}.
     */
    public synchronized LoopbackPayer on(String path, Function<Received, Reply> responder) {
        Objects.requireNonNull(responder, "responder");
        if (!path.startsWith("/") || path.equals("/")) {
            throw new IllegalArgumentException("route path must start with / and not be / itself: " + path);
        }
        if (routes.remove(path)) {
            server.removeContext(path);
        }
        server.createContext(path, handler(responder));
        routes.add(path);
        return this;
    }

    /** Answers every request under {@code path} with {@code reply}. */
    public LoopbackPayer on(String path, Reply reply) {
        Objects.requireNonNull(reply, "reply");
        return on(path, request -> reply);
    }

    /**
     * Answers successive requests under {@code path} with {@code replies}, in order, for example a 401
     * and then a 200. A request after the last reply is a test failure: its connection is dropped and
     * the next {@link #reset(Function)} or {@link #close()} reports it.
     */
    public LoopbackPayer onSequence(String path, Reply... replies) {
        List<Reply> script = List.of(replies);
        if (script.isEmpty()) {
            throw new IllegalArgumentException("a sequence needs at least one reply");
        }
        AtomicInteger next = new AtomicInteger();
        return on(path, request -> {
            int n = next.getAndIncrement();
            if (n < script.size()) {
                return script.get(n);
            }
            throw new AssertionError("LoopbackPayer: request " + (n + 1) + " under " + path + " ("
                    + request.method() + " " + request.rawPath() + "), but only " + script.size()
                    + " replies were scripted");
        });
    }

    /** Answers requests no route matches with {@code responder}; keeps routes and recorded requests. */
    public LoopbackPayer otherwise(Function<Received, Reply> responder) {
        this.fallback = Objects.requireNonNull(responder, "responder");
        return this;
    }

    /**
     * Removes every route, clears the recorded requests and answers every request with
     * {@code responder}: one server serves many property-test tries this way. If a responder failed
     * since the last reset, the payer is still reset, and then this throws that failure as
     * {@link #close()} does.
     */
    public synchronized void reset(Function<Received, Reply> responder) {
        Objects.requireNonNull(responder, "responder");
        for (String path : routes) {
            server.removeContext(path);
        }
        routes.clear();
        received.clear();
        this.fallback = responder;
        throwRecordedFailures();
    }

    /** Every recorded request, in arrival order. */
    public List<Received> received() {
        return List.copyOf(received);
    }

    /** The recorded requests whose raw path is exactly {@code rawPath}, in arrival order. */
    public List<Received> received(String rawPath) {
        return received.stream().filter(r -> r.rawPath().equals(rawPath)).toList();
    }

    /**
     * Stops the server, then fails with any responder failure or exhausted sequence recorded since the
     * last reset.
     */
    @Override
    public void close() {
        server.stop(0);
        threads.shutdownNow();
        throwRecordedFailures();
    }

    /** Clears the recorded failures and, if there were any, throws them as one error. */
    private void throwRecordedFailures() {
        List<Throwable> pending = List.copyOf(failures);
        failures.clear();
        if (!pending.isEmpty()) {
            AssertionError error = new AssertionError("LoopbackPayer: " + pending.size()
                    + " request(s) failed in the fake payer; first: " + pending.get(0), pending.get(0));
            pending.stream().skip(1).forEach(error::addSuppressed);
            throw error;
        }
    }

    private HttpHandler handler(Function<Received, Reply> responder) {
        return exchange -> {
            try {
                Received request = new Received(exchange.getRequestMethod(), exchange.getRequestURI().getRawPath(),
                        exchange.getRequestURI().getRawQuery(), exchange.getRequestHeaders(),
                        new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                received.add(request);
                Reply reply = responder.apply(request);
                reply.headers().forEach((name, values) -> exchange.getResponseHeaders().put(name, new ArrayList<>(values)));
                if (reply.body() == null) {
                    exchange.sendResponseHeaders(reply.status(), -1);
                    exchange.close();
                } else {
                    TestResponses.respond(exchange, reply.status(), reply.body());
                }
            } catch (RuntimeException | Error e) {
                failures.add(e);
                exchange.close();
                throw e;
            }
        };
    }
}
