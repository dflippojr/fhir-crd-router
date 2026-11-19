package io.github.dflippojr.fhircrdrouter.client.testsupport;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
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
 * even in a property-test try whose client expected the call to fail. Both first wait, up to a settle
 * bound (5 seconds unless given), for requests still running, and fail if one still is at the bound;
 * {@code LoopbackPayerFailureGridTest} checks each point at which a responder can fail.
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
     * from a hand-rolled server. Header names are case-insensitive, as in HTTP: names that differ only
     * in case are one header, and all of its values are sent.
     */
    public record Reply(int status, String body, Map<String, List<String>> headers) {
        public Reply {
            headers = Collections.unmodifiableMap(caseInsensitive(headers));
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
            Map<String, List<String>> next = caseInsensitive(headers);
            List<String> values = new ArrayList<>(next.getOrDefault(name, List.of()));
            values.add(value);
            next.put(name, values);
            return new Reply(status, body, next);
        }

        /** This reply without header {@code name}, for example to send a body with no Content-Type. */
        public Reply withoutHeader(String name) {
            Map<String, List<String>> next = caseInsensitive(headers);
            next.remove(name);
            return new Reply(status, body, next);
        }

        /** A mutable copy keyed case-insensitively, merging the values of names that differ only in case. */
        private static Map<String, List<String>> caseInsensitive(Map<String, List<String>> headers) {
            Map<String, List<String>> copy = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            headers.forEach((name, values) -> copy.merge(name, List.copyOf(values), (earlier, later) -> {
                List<String> merged = new ArrayList<>(earlier);
                merged.addAll(later);
                return List.copyOf(merged);
            }));
            return copy;
        }
    }

    private final HttpServer server;
    private final ExecutorService threads = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "loopback-payer");
        thread.setDaemon(true);
        return thread;
    });
    private final List<Received> received = new CopyOnWriteArrayList<>();
    private final FailureLedger failures = new FailureLedger();
    private final Set<String> routes = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicInteger inFlight = new AtomicInteger();
    private final Object settledLock = new Object();
    private final Duration settleBound;
    private volatile Function<Received, Reply> fallback = r -> new Reply(200, "{}");
    /** Test seam: runs inside the failure drain, after the drain has taken its snapshot. */
    volatile Runnable duringDrain = () -> { };

    public LoopbackPayer() {
        this(Duration.ofSeconds(5));
    }

    /**
     * A payer whose {@link #reset(Function)} and {@link #close()} wait up to {@code settleBound} for
     * running responders.
     */
    public LoopbackPayer(Duration settleBound) {
        this.settleBound = Objects.requireNonNull(settleBound, "settleBound");
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
     * {@code responder}: one server serves many property-test tries this way.
     *
     * <p>It first waits, up to the settle bound, for requests still running from the previous try, so
     * their failures belong to that try. Then it resets, and then it throws, as {@link #close()} does,
     * any responder failure since the last reset, and a responder still running at the bound. A
     * responder that fails after the bound is reported by the next reset or close.
     */
    public void reset(Function<Received, Reply> responder) {
        Objects.requireNonNull(responder, "responder");
        int stillRunning = awaitSettled();
        synchronized (this) {
            for (String path : routes) {
                server.removeContext(path);
            }
            routes.clear();
            received.clear();
            this.fallback = responder;
        }
        throwRecordedFailures(stillRunning);
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
     * Waits, up to the settle bound, for running requests to finish; then stops the server, interrupts
     * what is still running and waits up to the bound again for it to end. Then it fails with any
     * responder failure or exhausted sequence since the last reset, and with a responder still running
     * at the first bound. A second call stops nothing again; it reports only failures recorded since.
     */
    @Override
    public void close() {
        int stillRunning = 0;
        if (closed.compareAndSet(false, true)) {
            stillRunning = awaitSettled();
            server.stop(0);
            threads.shutdownNow();
            try {
                threads.awaitTermination(settleBound.toNanos(), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        throwRecordedFailures(stillRunning);
    }

    /**
     * Waits up to the settle bound for no handler to be running. Returns 0 when none is, otherwise how
     * many still were at the bound.
     */
    private int awaitSettled() {
        long deadline = System.nanoTime() + settleBound.toNanos();
        synchronized (settledLock) {
            while (inFlight.get() > 0) {
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    return inFlight.get();
                }
                try {
                    TimeUnit.NANOSECONDS.timedWait(settledLock, left);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return inFlight.get();
                }
            }
            return 0;
        }
    }

    /** Test seam: handlers running now, from reading the request to sending the reply. */
    int inFlight() {
        return inFlight.get();
    }

    /** Test seam: failures recorded and not yet reported. */
    int pendingFailures() {
        return failures.size();
    }

    /**
     * Drains the recorded failures in one step and, if there were any or a responder was still
     * running, throws them as one error.
     */
    private void throwRecordedFailures(int stillRunning) {
        List<Throwable> pending = failures.drain();
        duringDrain.run();
        if (pending.isEmpty() && stillRunning == 0) {
            return;
        }
        StringBuilder message = new StringBuilder("LoopbackPayer: ");
        if (stillRunning > 0) {
            message.append(stillRunning).append(" responder(s) still running after ").append(settleBound)
                    .append("; ");
        }
        message.append(pending.size()).append(" request(s) failed in the fake payer");
        if (!pending.isEmpty()) {
            message.append("; first: ").append(pending.get(0));
        }
        AssertionError error = new AssertionError(message.toString(), pending.isEmpty() ? null : pending.get(0));
        pending.stream().skip(1).forEach(error::addSuppressed);
        throw error;
    }

    /**
     * Responder failures not yet reported. Recording and draining share one lock, so a drain takes
     * exactly what was recorded before it and nothing recorded later is lost.
     */
    private static final class FailureLedger {
        private final List<Throwable> pending = new ArrayList<>();

        synchronized void record(Throwable failure) {
            pending.add(failure);
        }

        synchronized List<Throwable> drain() {
            List<Throwable> drained = List.copyOf(pending);
            pending.clear();
            return drained;
        }

        synchronized int size() {
            return pending.size();
        }
    }

    private HttpHandler handler(Function<Received, Reply> responder) {
        return exchange -> {
            inFlight.incrementAndGet();
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
                failures.record(e);
                exchange.close();
                throw e;
            } finally {
                if (inFlight.decrementAndGet() == 0) {
                    synchronized (settledLock) {
                        settledLock.notifyAll();
                    }
                }
            }
        };
    }
}
