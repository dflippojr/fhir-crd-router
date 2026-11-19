package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.client.testsupport.UnroutedGuard;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
    // Generous guard: catches a client that sleeps out a 120 s Retry-After without being sensitive to a slow runner.
    private static final Duration GUARD = Duration.ofSeconds(30);
    /** The hand-rolled server's answer to a path no context matched, so a request no route expects still fails. */
    private static final Reply NOT_FOUND = new Reply(404, "<h1>404 Not Found</h1>No context found for request",
            Map.of("Content-Type", List.of("text/html")));

    private LoopbackPayer payer;
    private ConnectionRecord record;
    private final AtomicInteger calls = new AtomicInteger();

    @BeforeEach
    void start() {
        payer = new LoopbackPayer();
        payer.otherwise(request -> NOT_FOUND);
        record = TestRecords.none(payer).payerId("PAYER-TEST").build();
    }

    @AfterEach
    void stop() {
        try {
            UnroutedGuard.assertUnroutedIsNotFound(payer);
        } finally {
            payer.close();
        }
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
        payer.on(HOOK_PATH, request -> {
            boolean first = calls.incrementAndGet() == 1;
            Reply reply = plain(first ? 429 : 200, first ? "slow down" : "{\"cards\":[]}");
            return first ? reply.withHeader("Retry-After", "1") : reply;
        });
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), null, null,
                Duration.ofSeconds(2), Duration.ofSeconds(1), seen::add)
                .retryPolicy(new RetryPolicy(2, Duration.ofSeconds(2)));
        long start = System.nanoTime();
        assertTimeoutPreemptively(GUARD, () -> client.callHookRaw(record, "hook", REQUEST));
        Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
        assertEquals(2, calls.get());
        assertEquals(List.of(1, 2), seen.stream().map(PayerExchange::attempt).toList());
        assertEquals(List.of(OptionalInt.of(429), OptionalInt.of(200)),
                seen.stream().map(PayerExchange::statusCode).toList());
        assertTrue(elapsed.compareTo(Duration.ofMillis(900)) >= 0);
    }

    @Test
    void givesUpWhenPayerAsksForMoreThanTheCap() {
        respond(429, Map.of("Retry-After", "120"));
        CdsHooksClient client = clientWith(new RetryPolicy(3, Duration.ofSeconds(2)));
        PayerCallException error = assertTimeoutPreemptively(GUARD, () -> assertThrows(PayerCallException.class,
                () -> client.callHookRaw(record, "hook", REQUEST)));
        assertEquals(Optional.of(Duration.ofSeconds(120)), error.retryAfter());
        assertEquals(1, calls.get());
    }

    @Test
    void stopsAtMaxAttempts() {
        respond(503, Map.of("Retry-After", "0"));
        assertThrows(PayerCallException.class, () -> clientWith(new RetryPolicy(3, Duration.ofSeconds(1)))
                .callHookRaw(record, "hook", REQUEST));
        assertEquals(3, calls.get());
    }

    /**
     * Characterization for #194: the single OAuth2 401 re-authentication is outside the
     * {@code maxAttempts} budget. Under {@code RetryPolicy(2, ...)} a 429, then a 401, then a 429 costs
     * the payer three attempts, and the second 429 is the failure.
     */
    @Test
    void oauthReauthenticationIsOutsideTheThrottleBudget() {
        AtomicInteger tokens = new AtomicInteger();
        List<Integer> statuses = new CopyOnWriteArrayList<>();
        payer.on("/token", request -> new Reply(200,
                "{\"access_token\":\"token-" + tokens.incrementAndGet() + "\",\"expires_in\":300}"));
        payer.on(HOOK_PATH, request -> {
            int status = calls.incrementAndGet() == 2 ? 401 : 429;
            statuses.add(status);
            Reply reply = plain(status, "throttled");
            return status == 429 ? reply.withHeader("Retry-After", "0") : reply;
        });
        ConnectionRecord oauth = TestRecords.oauth2(payer).payerId("PAYER-OAUTH").build();
        CdsHooksClient client = new CdsHooksClient(secretProvider("secret"))
                .retryPolicy(new RetryPolicy(2, Duration.ofSeconds(5)));

        PayerCallException error = assertTimeoutPreemptively(GUARD, () -> assertThrows(PayerCallException.class,
                () -> client.callHookRaw(oauth, "hook", REQUEST)));

        assertTrue(error.isRateLimited());
        assertEquals(List.of(429, 401, 429), statuses);
        assertEquals(3, calls.get());
        assertEquals(2, tokens.get());
    }

    @Test
    void doesNotRetryOtherStatusesOrMissingRetryAfter() {
        respond(500, Map.of("Retry-After", "0"));
        assertThrows(PayerCallException.class, () -> clientWith(new RetryPolicy(3, Duration.ofSeconds(1)))
                .callHookRaw(record, "hook", REQUEST));
        assertEquals(1, calls.get());

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

    private static CredentialProvider secretProvider(String secret) {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.of(secret); }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }

    /** Replaces the hook route with one that counts each call and answers {@code status} with {@code headers}. */
    private void respond(int status, Map<String, String> headers) {
        Reply reply = plain(status, "throttled");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            reply = reply.withHeader(header.getKey(), header.getValue());
        }
        Reply canned = reply;
        payer.on(HOOK_PATH, request -> {
            calls.incrementAndGet();
            return canned;
        });
    }

    /** {@code body} with no Content-Type, as the hand-rolled server sent it. */
    private static Reply plain(int status, String body) {
        return new Reply(status, body, Map.of());
    }
}
