package io.github.dflippojr.fhircrdrouter.client.auth;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener;
import io.github.dflippojr.fhircrdrouter.client.internal.EhrRedaction;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.time.Duration;
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
    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void aWaiterNeverSeesTheInitiatorsToken() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", e -> {
            e.getRequestBody().readAllBytes();
            received.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            e.getResponseHeaders().add("X-Request-Id", TOKEN_A);
            TestResponses.respond(e, 400, "{\"error\":\"invalid_client\",\"error_description\":\"saw " + TOKEN_A + "\"}");
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        ConnectionRecord record = ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                .baseUrl(base).authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).credentialRef("credential")
                .clientId("client").tokenEndpoint(base + "/token").build();
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
