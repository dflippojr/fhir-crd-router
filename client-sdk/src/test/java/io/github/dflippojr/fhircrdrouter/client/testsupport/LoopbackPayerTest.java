package io.github.dflippojr.fhircrdrouter.client.testsupport;

import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Received;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoopbackPayerTest {

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @Test
    void theDefaultFallbackAnswersAnUnroutedPathWithTheJdkServers404() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            HttpResponse<String> response = get(payer.url("/anything"));

            assertEquals(404, response.statusCode());
            assertEquals("<h1>404 Not Found</h1>No context found for request", response.body());
            assertEquals(Optional.of("text/html"), response.headers().firstValue("Content-Type"));
            assertEquals(1, payer.received("/anything").size(), "an unrouted request is still recorded");
        }
    }

    @Test
    void aRequestIsRecordedWithItsRawPathQueryHeadersAndBody() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/a", new Reply(200, "{}"));
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(payer.url("/a%2Fb/c?x=%20y&z")))
                    .header("Authorization", "Bearer synthetic")
                    .header("X-Custom", "one")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"k\":\"v\"}"))
                    .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode(), "the route answered");

            Received request = payer.received().get(0);
            assertEquals("POST", request.method());
            assertEquals("/a%2Fb/c", request.rawPath());
            assertEquals("x=%20y&z", request.rawQuery());
            assertEquals("{\"k\":\"v\"}", request.body());
            assertEquals("Bearer synthetic", request.authorization());
            assertEquals("one", request.header("x-custom"), "headers are looked up case-insensitively");
            assertEquals(List.of("one"), request.headers().get("X-CUSTOM"));
            assertNull(request.header("X-Absent"));
        }
    }

    @Test
    void aRequestWithoutAuthorizationRecordsNull() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/x", new Reply(200, "{}"));
            assertEquals(200, get(payer.url("/x")).statusCode(), "the route answered");

            assertNull(payer.received().get(0).authorization());
        }
    }

    @Test
    void theLongestRegisteredPrefixAnswersAndTheFallbackTakesTheRest() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/cds-services", new Reply(200, "\"discovery\""))
                    .on("/cds-services/hook", new Reply(200, "\"hook\""))
                    .otherwise(r -> Reply.empty(404));

            assertEquals("\"discovery\"", get(payer.url("/cds-services")).body());
            assertEquals("\"discovery\"", get(payer.url("/cds-services/other")).body());
            assertEquals("\"hook\"", get(payer.url("/cds-services/hook")).body());
            assertEquals(404, get(payer.url("/token")).statusCode());
        }
    }

    @Test
    void aRouteForTheSamePathReplacesTheEarlierOne() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/token", new Reply(200, "\"first\""));
            payer.on("/token", new Reply(200, "\"second\""));

            assertEquals("\"second\"", get(payer.url("/token")).body());
        }
    }

    @Test
    void otherwiseKeepsRoutesAndRecordedRequests() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/token", new Reply(200, "\"token\""));
            get(payer.url("/token"));

            payer.otherwise(r -> new Reply(418, "\"teapot\""));

            assertEquals("\"token\"", get(payer.url("/token")).body());
            assertEquals(418, get(payer.url("/other")).statusCode());
            assertEquals(3, payer.received().size());
        }
    }

    @Test
    void aSequenceAnswersInOrder() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.onSequence("/cds-services/hook", new Reply(401, "{}"), new Reply(200, "{\"cards\":[]}"));

            assertEquals(401, get(payer.url("/cds-services/hook")).statusCode());
            HttpResponse<String> second = get(payer.url("/cds-services/hook"));
            assertEquals(200, second.statusCode());
            assertEquals("{\"cards\":[]}", second.body());
        }
    }

    @Test
    void aRequestAfterTheLastScriptedReplyDropsTheConnectionAndFailsClose() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.onSequence("/token", new Reply(200, "{}"));
            get(payer.url("/token"));

            assertThrows(IOException.class, () -> post(payer.url("/token")));

            AssertionError failure = assertThrows(AssertionError.class, payer::close);
            assertTrue(failure.getMessage().contains("request 2 under /token"), failure.getMessage());
            assertTrue(failure.getMessage().contains("only 1 replies were scripted"), failure.getMessage());
        }
    }

    @Test
    void aResponderThatThrowsFailsCloseWithEveryFailure() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/check", r -> {
                throw new AssertionError("unexpected body " + r.body());
            });

            assertThrows(IOException.class, () -> post(payer.url("/check")));
            assertThrows(IOException.class, () -> post(payer.url("/check")));

            AssertionError failure = assertThrows(AssertionError.class, payer::close);
            assertTrue(failure.getMessage().startsWith("LoopbackPayer: 2 request(s) failed"),
                    failure.getMessage());
            assertEquals("unexpected body ", failure.getCause().getMessage());
            assertEquals(1, failure.getSuppressed().length);
            payer.close();
        }
    }

    @Test
    void anEmptyReplySendsNoBodyAndOnlyItsOwnHeaders() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/moved", Reply.empty(307).withHeader("Location", "/token"));

            HttpResponse<String> response = get(payer.url("/moved"));

            assertEquals(307, response.statusCode());
            assertEquals(Optional.of("/token"), response.headers().firstValue("Location"));
            assertEquals(Optional.empty(), response.headers().firstValue("Content-Type"));
            assertEquals(Optional.empty(), response.headers().firstValue("Transfer-Encoding"));
            assertEquals("", response.body());
        }
    }

    @Test
    void replyHeadersAreSentWithEveryValue() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/r", new Reply(429, "{}").withHeader("Retry-After", "7")
                    .withHeader("X-Multi", "a").withHeader("X-Multi", "b"));

            HttpResponse<String> response = get(payer.url("/r"));

            assertEquals(429, response.statusCode());
            assertEquals(Optional.of("7"), response.headers().firstValue("Retry-After"));
            assertEquals(List.of("a", "b"), response.headers().allValues("X-Multi"));
            assertEquals(Optional.of("application/json"), response.headers().firstValue("Content-Type"));
        }
    }

    @Test
    void withoutHeaderDropsTheContentType() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/plain", new Reply(400, "not json").withoutHeader("Content-Type"));

            HttpResponse<String> response = get(payer.url("/plain"));

            assertEquals(Optional.empty(), response.headers().firstValue("Content-Type"));
            assertEquals("not json", response.body());
        }
    }

    @Test
    void replyHeaderNamesAreCaseInsensitiveLikeHttpHeaders() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/added", new Reply(200, "{}").withHeader("X-Multi", "a").withHeader("x-multi", "b"));
            payer.on("/removed", new Reply(200, "{}").withoutHeader("content-type"));
            payer.on("/given", new Reply(200, "{}", Map.of("X-One", List.of("a"))).withHeader("x-ONE", "b"));

            assertEquals(List.of("a", "b"), get(payer.url("/added")).headers().allValues("X-Multi"));
            assertEquals(Optional.empty(), get(payer.url("/removed")).headers().firstValue("Content-Type"));
            assertEquals(List.of("a", "b"), get(payer.url("/given")).headers().allValues("X-One"));
        }
    }

    @Test
    void anExplicitHeaderMapIsSentAsGiven() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/x", new Reply(200, "text", Map.of("Content-Type", List.of("text/plain"))));

            assertEquals(Optional.of("text/plain"), get(payer.url("/x")).headers().firstValue("Content-Type"));
        }
    }

    @Test
    void respondersRunConcurrentlySoOneCanBlockOnAnother() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            CountDownLatch bothInside = new CountDownLatch(2);
            payer.on("/block", r -> {
                bothInside.countDown();
                try {
                    return new Reply(bothInside.await(5, TimeUnit.SECONDS) ? 200 : 504, "{}");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return Reply.empty(500);
                }
            });

            CompletableFuture<HttpResponse<String>> first = getAsync(payer.url("/block"));
            CompletableFuture<HttpResponse<String>> second = getAsync(payer.url("/block"));

            assertEquals(200, first.get(10, TimeUnit.SECONDS).statusCode());
            assertEquals(200, second.get(10, TimeUnit.SECONDS).statusCode());
        }
    }

    @Test
    void aRequestIsRecordedBeforeItsResponderAnswers() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            CountDownLatch release = new CountDownLatch(1);
            payer.on("/slow", r -> {
                try {
                    release.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return new Reply(200, "{}");
            });

            CompletableFuture<HttpResponse<String>> pending = getAsync(payer.url("/slow"));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (payer.received().isEmpty() && System.nanoTime() < deadline) {
                Thread.onSpinWait();
            }
            assertEquals(1, payer.received().size(), "recorded while the responder still blocks");
            release.countDown();
            assertEquals(200, pending.get(10, TimeUnit.SECONDS).statusCode());
        }
    }

    @Test
    void receivedByPathMatchesTheRawPathExactly() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/token", new Reply(200, "{}")).on("/token-other", new Reply(200, "{}"));
            assertEquals(200, get(payer.url("/token")).statusCode(), "the route answered");
            assertEquals(200, get(payer.url("/token-other")).statusCode(), "the route answered");
            assertEquals(200, get(payer.url("/token?x=1")).statusCode(), "the route answered");

            assertEquals(2, payer.received("/token").size());
            assertEquals(1, payer.received("/token-other").size());
            assertEquals(List.of(), payer.received("/tok"));
        }
    }

    @Test
    void resetRemovesRoutesAndClearsRecordedRequests() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/token", new Reply(200, "\"route\""));
            get(payer.url("/token"));

            payer.reset(r -> new Reply(202, "\"after\""));

            assertEquals(List.of(), payer.received());
            HttpResponse<String> response = get(payer.url("/token"));
            assertEquals(202, response.statusCode());
            assertEquals("\"after\"", response.body());
            assertEquals(1, payer.received().size());
        }
    }

    /** A property test resets once per try, so a try's responder failure must not be erased by the next. */
    @Test
    void resetThrowsAResponderFailureFromThePreviousTryAndStillResets() throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.on("/token", r -> {
                throw new AssertionError("failed in the previous try");
            });
            assertThrows(IOException.class, () -> post(payer.url("/token")));

            AssertionError failure = assertThrows(AssertionError.class,
                    () -> payer.reset(r -> new Reply(202, "\"after\"")));
            assertEquals("failed in the previous try", failure.getCause().getMessage());

            assertEquals(List.of(), payer.received());
            assertEquals(202, get(payer.url("/token")).statusCode(), "the reset still took effect");
            payer.reset(r -> new Reply(200, "{}"));
        }
    }

    @Test
    void urlAppendsThePathToTheLoopbackOrigin() {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            assertTrue(payer.origin().matches("http://127\\.0\\.0\\.1:\\d+"), payer.origin());
            assertEquals(payer.origin() + "/cds-services", payer.url("/cds-services"));
        }
    }

    @Test
    void invalidRoutesAndEmptySequencesAreRefused() {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            assertThrows(IllegalArgumentException.class, () -> payer.on("/", new Reply(200, "{}")));
            assertThrows(IllegalArgumentException.class, () -> payer.on("token", new Reply(200, "{}")));
            assertThrows(IllegalArgumentException.class, () -> payer.onSequence("/token"));
            assertThrows(NullPointerException.class, () -> payer.on("/token", (Reply) null));
        }
    }

    private HttpResponse<String> get(String url) throws IOException, InterruptedException {
        return http.send(request(url), HttpResponse.BodyHandlers.ofString());
    }

    /** A POST, which the JDK client does not retry when the connection drops, unlike a GET. */
    private void post(String url) throws IOException, InterruptedException {
        http.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
    }

    private CompletableFuture<HttpResponse<String>> getAsync(String url) {
        return http.sendAsync(request(url), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpRequest request(String url) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build();
    }
}
