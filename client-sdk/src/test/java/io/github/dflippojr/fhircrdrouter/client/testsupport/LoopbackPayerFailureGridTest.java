package io.github.dflippojr.fhircrdrouter.client.testsupport;

import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Received;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Class-level check for "a responder failure cannot fail silently" (#234, review rounds r1 and r2): every
 * point at which a responder can fail, crossed with both ways it can fail, must be reported exactly once,
 * by {@link LoopbackPayer#reset(Function)} or {@link LoopbackPayer#close()}.
 *
 * <p>Rows: before a reset; concurrently with the drain; still in flight at a reset; still in flight at a
 * close; after a client timeout but before a close; still running at the bound of a close or a reset; and
 * a stress loop of resets racing failing requests.
 */
class LoopbackPayerFailureGridTest {

    private static final Pattern FAILED = Pattern.compile("(\\d+) request\\(s\\) failed");
    private static final Function<Received, Reply> THROWS = r -> {
        throw new AssertionError("throwing responder");
    };

    private final HttpClient http = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).build();

    /** The two ways a request fails in the fake payer. */
    enum Kind {
        THROWING_RESPONDER, EXHAUSTED_SEQUENCE;

        /** Makes the next POST to {@code path} fail in the fake payer. */
        void arm(LoopbackPayer payer, String path, HttpClient http) throws Exception {
            if (this == THROWING_RESPONDER) {
                payer.on(path, THROWS);
            } else {
                payer.onSequence(path, Reply.empty(204));
                assertEquals(204, http.send(post(payer.url(path)), HttpResponse.BodyHandlers.ofString())
                        .statusCode(), "the one scripted reply");
            }
        }
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aFailureBeforeAResetIsReportedOnceByTheReset(Kind kind) throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            kind.arm(payer, "/p", http);
            assertThrows(IOException.class, () -> send(payer.url("/p")));

            assertEquals(1, reported(() -> payer.reset(r -> new Reply(200, "{}"))));
            assertEquals(0, reported(payer::close));
        }
    }

    /**
     * The drain hook releases a latch that a client waits on, and holds the drain until the client's
     * request has failed in the payer. A drain that clears what it did not snapshot loses that failure.
     */
    @ParameterizedTest
    @EnumSource(Kind.class)
    void aFailureDuringTheDrainIsReportedOnceByTheNextDrain(Kind kind) throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            CountDownLatch go = new CountDownLatch(1);
            CompletableFuture<Boolean> failed = CompletableFuture.supplyAsync(() -> {
                try {
                    assertTrue(go.await(10, TimeUnit.SECONDS));
                    send(payer.url("/late"));
                    return false;
                } catch (IOException e) {
                    return true;
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            payer.duringDrain = () -> {
                payer.duringDrain = () -> { };
                try {
                    kind.arm(payer, "/late", http);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
                go.countDown();
                awaitTrue(() -> payer.pendingFailures() > 0, "the request failed inside the drain");
            };

            assertEquals(0, reported(() -> payer.reset(r -> new Reply(200, "{}"))));
            assertTrue(failed.get(10, TimeUnit.SECONDS), "the request failed in the payer");
            assertEquals(1, reported(payer::close), "the failure recorded during the drain survives it");
        }
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aRequestStillInFlightAtAResetIsAwaitedAndReportedOnce(Kind kind) throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            kind.arm(payer, "/p", http);
            CountDownLatch gate = new CountDownLatch(1);
            CompletableFuture<?> pending = gatedSend(payer.url("/p"), gate);
            awaitTrue(() -> payer.inFlight() == 1, "the request reached the payer");

            releaseLater(gate);
            assertEquals(1, reported(() -> payer.reset(r -> new Reply(200, "{}"))));

            assertTrue(pending.handle((r, e) -> e != null).get(10, TimeUnit.SECONDS));
            assertEquals(0, reported(payer::close));
        }
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aRequestStillInFlightAtCloseIsAwaitedAndReportedOnce(Kind kind) throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            kind.arm(payer, "/p", http);
            CountDownLatch gate = new CountDownLatch(1);
            gatedSend(payer.url("/p"), gate);
            awaitTrue(() -> payer.inFlight() == 1, "the request reached the payer");

            releaseLater(gate);
            assertEquals(1, reported(payer::close));
            assertEquals(0, reported(payer::close));
        }
    }

    /**
     * Only a throwing responder can fail after the client gave up: a scripted sequence answers at once,
     * so its in-flight form is {@link #aRequestStillInFlightAtCloseIsAwaitedAndReportedOnce}.
     */
    @Test
    void aResponderFailingAfterAClientTimeoutIsReportedOnceByClose() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            CountDownLatch started = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            payer.on("/slow", r -> {
                started.countDown();
                awaitIgnoringInterrupts(release);
                spinFor(Duration.ofMillis(100));
                throw new AssertionError("failed after the client timed out");
            });

            assertThrows(HttpTimeoutException.class, () -> http.send(HttpRequest.newBuilder(
                    URI.create(payer.url("/slow"))).timeout(Duration.ofMillis(300))
                    .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString()));
            assertTrue(started.await(5, TimeUnit.SECONDS));

            release.countDown();
            assertEquals(1, reported(payer::close));
        }
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aRequestStillRunningAtTheBoundFailsClose(Kind kind) throws Exception {
        CountDownLatch gate = new CountDownLatch(1);
        try (LoopbackPayer payer = new LoopbackPayer(Duration.ofMillis(200))) {
            kind.arm(payer, "/p", http);
            gatedSend(payer.url("/p"), gate);
            awaitTrue(() -> payer.inFlight() == 1, "the request reached the payer");

            AssertionError failure = assertThrows(AssertionError.class, payer::close);
            assertTrue(failure.getMessage().contains("1 responder(s) still running after PT0.2S"),
                    failure.getMessage());
        } finally {
            gate.countDown();
        }
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aRequestStillRunningAtTheBoundFailsResetWhichStillResetsAndTheLateFailureIsReportedOnce(Kind kind)
            throws Exception {
        CountDownLatch gate = new CountDownLatch(1);
        try (LoopbackPayer payer = new LoopbackPayer(Duration.ofMillis(200))) {
            kind.arm(payer, "/p", http);
            CompletableFuture<?> pending = gatedSend(payer.url("/p"), gate);
            awaitTrue(() -> payer.inFlight() == 1, "the request reached the payer");

            AssertionError failure = assertThrows(AssertionError.class,
                    () -> payer.reset(r -> new Reply(202, "{}")));
            assertTrue(failure.getMessage().contains("1 responder(s) still running after PT0.2S"),
                    failure.getMessage());
            assertEquals(202, http.send(post(payer.url("/other")), HttpResponse.BodyHandlers.ofString())
                    .statusCode(), "the reset still took effect");

            gate.countDown();
            assertTrue(pending.handle((r, e) -> e != null).get(10, TimeUnit.SECONDS));
            assertEquals(1, reported(payer::close), "the late failure is reported by the next drain");
        } finally {
            gate.countDown();
        }
    }

    /**
     * Resets race failing requests of both kinds; every failure is reported exactly once across all the
     * drains.
     */
    @Test
    @Timeout(120)
    void resetsRacingFailingRequestsReportEveryFailureExactlyOnce() throws Exception {
        int iterations = 200;
        int expected = 0;
        int reported = 0;
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.reset(THROWS);
            for (int i = 0; i < iterations; i++) {
                String path = "/any";
                if (i % 2 == 1) {
                    Kind.EXHAUSTED_SEQUENCE.arm(payer, "/seq", http);
                    path = "/seq";
                }
                CompletableFuture<Boolean> failed = http.sendAsync(post(payer.url(path)),
                        HttpResponse.BodyHandlers.ofString()).handle((r, e) -> e != null);
                reported += reported(() -> payer.reset(THROWS));
                expected += failed.get(10, TimeUnit.SECONDS) ? 1 : 0;
            }
            reported += reported(payer::close);
        }
        assertEquals(iterations, expected, "every request failed in the payer");
        assertEquals(expected, reported, "each failure reported exactly once");
    }

    /** How many request failures {@code drain} reported: 0 when it did not throw. */
    private static int reported(Runnable drain) {
        try {
            drain.run();
            return 0;
        } catch (AssertionError e) {
            Matcher m = FAILED.matcher(String.valueOf(e.getMessage()));
            assertTrue(m.find(), "not a LoopbackPayer failure report: " + e.getMessage());
            return Integer.parseInt(m.group(1));
        }
    }

    private void send(String url) throws IOException, InterruptedException {
        http.send(post(url), HttpResponse.BodyHandlers.ofString());
    }

    /** A POST, which the JDK client does not retry when the connection drops. */
    private static HttpRequest post(String url) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.noBody()).build();
    }

    /**
     * A POST whose chunked body sends one byte, then waits for {@code gate} before it ends, so the payer's
     * handler is running (reading the body) until the gate opens.
     */
    private CompletableFuture<HttpResponse<String>> gatedSend(String url, CountDownLatch gate) {
        Flow.Publisher<ByteBuffer> body = subscriber -> subscriber.onSubscribe(new Flow.Subscription() {
            private final AtomicBoolean sent = new AtomicBoolean();

            @Override
            public void request(long n) {
                if (sent.compareAndSet(false, true)) {
                    subscriber.onNext(ByteBuffer.wrap(new byte[] {'x'}));
                    CompletableFuture.runAsync(() -> {
                        awaitIgnoringInterrupts(gate);
                        subscriber.onComplete();
                    });
                }
            }

            @Override
            public void cancel() {
                // the gate still opens on its own
            }
        });
        return http.sendAsync(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.fromPublisher(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /** Opens {@code gate} 100 ms from now, from another thread. */
    private static void releaseLater(CountDownLatch gate) {
        Thread releaser = new Thread(() -> {
            spinFor(Duration.ofMillis(100));
            gate.countDown();
        });
        releaser.setDaemon(true);
        releaser.start();
    }

    private static void awaitIgnoringInterrupts(CountDownLatch latch) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        boolean interrupted = false;
        while (latch.getCount() > 0 && System.nanoTime() < deadline) {
            try {
                latch.await(50, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /** Waits {@code duration} without reacting to interrupts, as a busy responder would. */
    private static void spinFor(Duration duration) {
        long deadline = System.nanoTime() + duration.toNanos();
        boolean interrupted = false;
        while (System.nanoTime() < deadline) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                interrupted = true; // keep going: this stands in for work that does not check for interrupts
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void awaitTrue(BooleanSupplier condition, String what) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertTrue(condition.getAsBoolean(), "timed out waiting: " + what);
    }
}
