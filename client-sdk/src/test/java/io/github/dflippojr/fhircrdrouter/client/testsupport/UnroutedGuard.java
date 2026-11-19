package io.github.dflippojr.fhircrdrouter.client.testsupport;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Checks that a {@link LoopbackPayer} answers a path no route matches with 404, as a hand-rolled
 * {@code HttpServer} did for a path with no context. A test class that sets a 404 fallback calls
 * this in {@code @AfterEach}, before closing the payer, so deleting the fallback fails the suite.
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
                    + " instead of the hand-rolled server's 404: the class's NOT_FOUND fallback is missing");
        }
    }
}
