package io.github.dflippojr.fhircrdrouter.client;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RetryAfterTest {
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance", Map.of(), Map.of());
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2015-10-21T07:28:00Z"), ZoneOffset.UTC);
    private static final String HOOK_PATH = "/cds-services/hook";
    private HttpServer server;
    private ConnectionRecord record;
    private final AtomicInteger calls = new AtomicInteger();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
        record = ConnectionRecord.builder().payerId("PAYER-TEST").environment(Environment.SANDBOX)
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort()).authType(AuthType.NONE).build();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void parsesSecondsAndHttpDate() {
        assertEquals(Optional.of(Duration.ofSeconds(7)), PayerCallException.parseRetryAfter(" 7 ", CLOCK));
        assertEquals(Optional.of(Duration.ofSeconds(90)),
                PayerCallException.parseRetryAfter("Wed, 21 Oct 2015 07:29:30 GMT", CLOCK));
    }

    @Test
    void pastDateClampsToZeroAndGarbageIsEmpty() {
        assertEquals(Optional.of(Duration.ZERO),
                PayerCallException.parseRetryAfter("Wed, 21 Oct 2015 07:00:00 GMT", CLOCK));
        for (String bad : List.of("", "soon", "-5", "1.5", "99999999999999999999", "Wed, 99 Oct 2015 07:00:00 GMT")) {
            assertTrue(PayerCallException.parseRetryAfter(bad, CLOCK).isEmpty(), bad);
        }
    }

    @Test
    void exceptionExposesRetryAfterAndRateLimited() {
        respond(429, Map.of("Retry-After", "3"));
        PayerCallException error = assertThrows(PayerCallException.class, this::callWithoutRetry);
        assertTrue(error.isRateLimited());
        assertEquals(Optional.of(Duration.ofSeconds(3)), error.retryAfter());
        assertEquals(1, calls.get());
    }

    @Test
    void missingHeaderAndOtherStatusesAreNotRateLimitedOrTimed() {
        respond(503, Map.of());
        PayerCallException error = assertThrows(PayerCallException.class, this::callWithoutRetry);
        assertFalse(error.isRateLimited());
        assertTrue(error.retryAfter().isEmpty());
    }

    @Test
    void defaultConfigurationDoesNotRetry() {
        respond(429, Map.of("Retry-After", "0"));
        assertThrows(PayerCallException.class, this::callWithoutRetry);
        assertEquals(1, calls.get());
    }

    @Test
    void retrySucceedsAfter429AndListenerSeesBothAttempts() {
        List<PayerExchange> seen = new CopyOnWriteArrayList<>();
        server.createContext(HOOK_PATH, exchange -> {
            boolean first = calls.incrementAndGet() == 1;
            if (first) {
                exchange.getResponseHeaders().add("Retry-After", "1");
            }
            TestResponses.respond(exchange, first ? 429 : 200, first ? "slow down" : "{\"cards\":[]}");
        });
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), null, null,
                Duration.ofSeconds(2), Duration.ofSeconds(1), seen::add)
                .retryPolicy(new RetryPolicy(2, Duration.ofSeconds(2)));
        long start = System.nanoTime();
        client.callHookRaw(record, "hook", REQUEST);
        Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
        assertEquals(2, calls.get());
        assertEquals(List.of(1, 2), seen.stream().map(PayerExchange::attempt).toList());
        assertEquals(List.of(OptionalInt.of(429), OptionalInt.of(200)),
                seen.stream().map(PayerExchange::statusCode).toList());
        assertTrue(elapsed.compareTo(Duration.ofMillis(900)) >= 0);
        assertTrue(elapsed.compareTo(Duration.ofSeconds(2)) < 0);
    }

    @Test
    void givesUpWhenPayerAsksForMoreThanTheCap() {
        respond(429, Map.of("Retry-After", "120"));
        CdsHooksClient client = clientWith(new RetryPolicy(3, Duration.ofSeconds(2)));
        long start = System.nanoTime();
        PayerCallException error = assertThrows(PayerCallException.class,
                () -> client.callHookRaw(record, "hook", REQUEST));
        assertEquals(Optional.of(Duration.ofSeconds(120)), error.retryAfter());
        assertEquals(1, calls.get());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(2)) < 0);
    }

    @Test
    void stopsAtMaxAttempts() {
        respond(503, Map.of("Retry-After", "0"));
        assertThrows(PayerCallException.class, () -> clientWith(new RetryPolicy(3, Duration.ofSeconds(1)))
                .callHookRaw(record, "hook", REQUEST));
        assertEquals(3, calls.get());
    }

    @Test
    void doesNotRetryOtherStatusesOrMissingRetryAfter() {
        respond(500, Map.of("Retry-After", "0"));
        assertThrows(PayerCallException.class, () -> clientWith(new RetryPolicy(3, Duration.ofSeconds(1)))
                .callHookRaw(record, "hook", REQUEST));
        assertEquals(1, calls.get());

        server.removeContext(HOOK_PATH);
        calls.set(0);
        respond(429, Map.of());
        assertThrows(PayerCallException.class, () -> clientWith(new RetryPolicy(3, Duration.ofSeconds(1)))
                .callHookRaw(record, "hook", REQUEST));
        assertEquals(1, calls.get());
    }

    @Test
    void policyValidatesArguments() {
        assertThrows(IllegalArgumentException.class, () -> new RetryPolicy(0, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new RetryPolicy(2, Duration.ofSeconds(-1)));
        assertThrows(NullPointerException.class, () -> new RetryPolicy(2, null));
        assertThrows(NullPointerException.class, () -> clientWith(RetryPolicy.NONE).retryPolicy(null));
    }

    private CdsHooksClient clientWith(RetryPolicy policy) {
        return new CdsHooksClient(HttpClient.newHttpClient(), null, null, Duration.ofSeconds(2), Duration.ofSeconds(1))
                .retryPolicy(policy);
    }

    private void callWithoutRetry() {
        clientWith(RetryPolicy.NONE).callHookRaw(record, "hook", REQUEST);
    }

    private void respond(int status, Map<String, String> headers) {
        server.createContext(HOOK_PATH, exchange -> {
            calls.incrementAndGet();
            headers.forEach((k, v) -> exchange.getResponseHeaders().add(k, v));
            TestResponses.respond(exchange, status, "throttled");
        });
    }
}
