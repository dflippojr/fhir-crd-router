package io.github.dflippojr.fhircrdrouter.client.auth;

import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener;
import io.github.dflippojr.fhircrdrouter.client.internal.EhrRedaction;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.client.testsupport.UnroutedGuard;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A token fetch shared by concurrent calls fails once; each call sees that failure redacted under the
 * context of the call that sent it, before any other call can see it (#164).
 */
class SharedFlightRedactionTest {
    private static final String TOKEN_A = "SharedFlightEhrTokenA164";
    /** The hand-rolled server's answer to a path no context matched, so a request no route expects still fails. */
    private static final Reply NOT_FOUND = new Reply(404, "<h1>404 Not Found</h1>No context found for request",
            Map.of("Content-Type", List.of("text/html")));

    private final LoopbackPayer payer = new LoopbackPayer();

    @BeforeEach
    void routesOnly() {
        payer.otherwise(request -> NOT_FOUND);
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
    void aWaiterNeverSeesTheInitiatorsToken() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        payer.on("/token", request -> {
            received.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return new Reply(400, "{\"error\":\"invalid_client\",\"error_description\":\"saw " + TOKEN_A + "\"}",
                    Map.of("X-Request-Id", List.of(TOKEN_A)));
        });
        ConnectionRecord record = TestRecords.oauth2(payer).payerId("payer").build();
        OAuth2TokenClient tokens = new OAuth2TokenClient(HttpClient.newHttpClient(), Duration.ofSeconds(10),
                PayerExchangeListener.NOOP);
        AtomicReference<Throwable> seenByA = new AtomicReference<>();
        AtomicReference<Throwable> seenByB = new AtomicReference<>();

        Thread a = new Thread(() -> {
            try (EhrRedaction.Scope ignored = EhrRedaction.of(TOKEN_A).open()) {
                tokens.fetchAccessToken(record, "secret");
            } catch (Throwable t) {
                seenByA.set(t);
            }
        });
        a.start();
        assertTrue(received.await(10, TimeUnit.SECONDS), "A's request reached the token endpoint");
        Thread b = new Thread(() -> {
            try {
                tokens.fetchAccessToken(record, "secret");
            } catch (Throwable t) {
                seenByB.set(t);
            }
        });
        b.start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (b.getState() != Thread.State.WAITING && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertEquals(Thread.State.WAITING, b.getState(), "B joined A's flight");
        release.countDown();
        a.join(10_000);
        b.join(10_000);

        for (Throwable seen : new Throwable[] {seenByA.get(), seenByB.get()}) {
            PayerCallException failure = assertInstanceOf(PayerCallException.class, seen);
            assertEquals(400, failure.statusCode().orElseThrow());
            assertFalse(printed(failure).contains(TOKEN_A), printed(failure));
            assertFalse(failure.responseBody().contains(TOKEN_A), failure.responseBody());
            assertFalse(failure.responseHeaders().map().toString().contains(TOKEN_A),
                    failure.responseHeaders().map().toString());
        }
    }

    private static String printed(Throwable error) {
        StringWriter out = new StringWriter();
        error.printStackTrace(new PrintWriter(out));
        return out.toString();
    }
}
