package io.github.dflippojr.fhircrdrouter.client.testsupport;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Checks that a {@link LoopbackPayer} answers a path no route matches with 404, as a hand-rolled
 * {@code HttpServer} did for a path with no context. A test class calls this in {@code @AfterEach},
 * before closing the payer, so a class whose fallback answers an unrouted path with anything else fails
 * the suite. {@code LoopbackPayerTest} pins the payer's own 404 default, {@link LoopbackPayer#NOT_FOUND}.
 */
public final class UnroutedGuard {

    /** A path no test registers a route for. */
    public static final String PATH = "/unrouted-probe";

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private UnroutedGuard() {
    }

    /** Sends a GET to {@link #PATH} on {@code payer} and fails unless the status is 404. */
    public static void assertUnroutedIsNotFound(LoopbackPayer payer) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(payer.url(PATH))).timeout(TIMEOUT).GET().build();
        int status;
        try {
            status = HttpClient.newBuilder().connectTimeout(TIMEOUT).build()
                    .send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (IOException e) {
            throw new AssertionError("unrouted-path guard could not reach the payer", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("unrouted-path guard was interrupted", e);
        }
        if (status != 404) {
            throw new AssertionError("an unrouted path got HTTP " + status
                    + " instead of the hand-rolled server's 404: the payer's fallback no longer answers"
                    + " unrouted paths with NOT_FOUND");
        }
    }
}
