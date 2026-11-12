package io.github.dflippojr.fhircrdrouter.client.internal;

import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.net.ssl.SSLSession;

import static org.junit.jupiter.api.Assertions.*;

/** The per-call context and the exception boundary of {@link EhrRedaction} (#164). */
class EhrRedactionTest {
    private static final String TOKEN = "ctxToken164";
    private static final URI URI_ = URI.create("https://payer.example.org/cds-services/x");
    private final EhrRedaction redaction = EhrRedaction.of(TOKEN);

    @Test
    void contextIsPerThreadAndScopesNest() {
        assertSame(EhrRedaction.NONE, EhrRedaction.of(null));
        assertSame(EhrRedaction.NONE, EhrRedaction.of(""));
        assertSame(EhrRedaction.NONE, EhrRedaction.current());
        try (EhrRedaction.Scope outer = redaction.open()) {
            assertEquals(TOKEN, EhrRedaction.current().token());
            try (EhrRedaction.Scope inner = EhrRedaction.of("other").open()) {
                assertEquals("other", EhrRedaction.current().token());
            }
            assertEquals(TOKEN, EhrRedaction.current().token());
        }
        assertSame(EhrRedaction.NONE, EhrRedaction.current());
    }

    @Test
    void textRedactsOrFallsBackToTheMarker() {
        assertNull(redaction.text(null));
        assertEquals("x", EhrRedaction.NONE.text("x"));
        assertEquals("a [REDACTED] b", redaction.text("a " + TOKEN + " b"));
        assertEquals("[REDACTED]", redaction.text("a \\u0063txToken164"));
    }

    @Test
    void withoutATokenExceptionsPassThroughAndWithOneTheyAreAlwaysFresh() {
        RouterException leaky = new RouterException(TOKEN);
        assertSame(leaky, EhrRedaction.NONE.exception(leaky));
        RouterException clean = new RouterException("fine", new IOException("also fine"));
        RuntimeException fresh = redaction.exception(clean);
        assertNotSame(clean, fresh);
        assertNull(fresh.getCause());
        assertEquals("fine (cause: java.io.IOException)", fresh.getMessage());
        assertArrayEquals(clean.getStackTrace(), fresh.getStackTrace());
    }

    @Test
    void eachExceptionClassIsCopiedWithoutTheToken() {
        assertCopy(new RouterException("m " + TOKEN, new IOException(TOKEN)), RouterException.class);
        assertCopy(new IllegalArgumentException("m " + TOKEN), IllegalArgumentException.class);
        assertCopy(new IllegalStateException("m", new IllegalStateException(TOKEN)), IllegalStateException.class);
        RuntimeException other = assertCopy(new UnsupportedOperationException(TOKEN), RouterException.class);
        assertTrue(other.getMessage().startsWith(UnsupportedOperationException.class.getName()), other.getMessage());
        RouterException suppressed = new RouterException("m");
        suppressed.addSuppressed(new IOException(TOKEN));
        assertEquals(0, assertCopy(suppressed, RouterException.class).getSuppressed().length);
        RuntimeException withError = assertCopy(new RouterException("m", new AssertionError(TOKEN)), RouterException.class);
        assertEquals("m (cause: java.lang.AssertionError)", withError.getMessage());
    }

    @Test
    void payerCallExceptionsKeepTheirFields() {
        PayerCallException transport = PayerCallException.transport("failed " + TOKEN, PayerCallPhase.TOKEN, "payer",
                URI_, new IOException(TOKEN));
        PayerCallException safeTransport = (PayerCallException) assertCopy(transport, PayerCallException.class);
        assertTrue(safeTransport.statusCode().isEmpty());
        assertEquals(PayerCallPhase.TOKEN, safeTransport.phase());
        assertFalse(safeTransport.timedOut());
        PayerCallException timeout = PayerCallException.transport("timed out", PayerCallPhase.HOOK, "payer", URI_,
                new java.net.http.HttpTimeoutException("slow"));
        PayerCallException safeTimeout = (PayerCallException) redaction.exception(timeout);
        assertTrue(safeTimeout.timedOut());
        assertNull(safeTimeout.getCause());

        HttpHeaders headers = HttpHeaders.of(Map.of("X-Request-Id", List.of(TOKEN), "Retry-After", List.of("5")),
                (k, v) -> true);
        PayerCallException http = new PayerCallException("Hook failed: ", PayerCallPhase.HOOK, "payer", URI_,
                response(503, headers), "{\"error\":\"" + TOKEN + "\"}");
        PayerCallException safeHttp = (PayerCallException) assertCopy(http, PayerCallException.class);
        assertEquals(503, safeHttp.statusCode().orElseThrow());
        assertEquals("{\"error\":\"[REDACTED]\"}", safeHttp.responseBody());
        assertEquals("Hook failed: {\"error\":\"[REDACTED]\"}", safeHttp.getMessage());
        assertEquals(List.of("[REDACTED]"), safeHttp.responseHeaders().allValues("X-Request-Id"));
        assertEquals(Optional.of(java.time.Duration.ofSeconds(5)), safeHttp.retryAfter());

        PayerCallException headerOnly = new PayerCallException("Hook failed: ", PayerCallPhase.HOOK, "payer", URI_,
                response(500, headers), null);
        assertCopy(headerOnly, PayerCallException.class);
        PayerCallException hidden = new PayerCallException("Hook failed: ", PayerCallPhase.HOOK, "payer", URI_,
                response(500, HttpHeaders.of(Map.of(), (k, v) -> true)), "<p>\\u0063txToken164</p>");
        assertEquals("[REDACTED]", ((PayerCallException) assertCopy(hidden, PayerCallException.class)).responseBody());
    }

    @Test
    void aCopyThatWouldStillShowTheTokenFallsBackToTheClassName() {
        RouterException named = new RouterException("x") {
            @Override
            public String toString() {
                return "named " + TOKEN;
            }
        };
        RuntimeException safe = redaction.exception(named);
        assertEquals(RouterException.class, safe.getClass());
        assertFalse(printed(safe).contains(TOKEN), printed(safe));
    }

    @Test
    void stackFramesThatShowTheTokenAreRedacted() {
        RouterException error = new RouterException("m");
        StackTraceElement frame = new StackTraceElement("loader", "module", "1", "a.B", "run", TOKEN + ".java", 7);
        error.setStackTrace(new StackTraceElement[] {frame, error.getStackTrace()[0]});
        error.initCause(new IOException("cause"));
        error.getCause().setStackTrace(new StackTraceElement[] {frame});

        RuntimeException safe = redaction.exception(error);

        assertFalse(printed(safe).contains(TOKEN), printed(safe));
        assertEquals("a.B", safe.getStackTrace()[0].getClassName());
        assertEquals(7, safe.getStackTrace()[0].getLineNumber());
        assertEquals(error.getStackTrace()[1], safe.getStackTrace()[1]);
        assertFalse(printed(ExchangeSender.safeError(new IOException("x") {
            @Override public StackTraceElement[] getStackTrace() { return new StackTraceElement[] {frame}; }
            @Override public String getMessage() { return TOKEN; }
        }, TOKEN, false)).contains(TOKEN));
    }

    @Test
    void uriThatNamesTheTokenIsRedacted() {
        for (String raw : List.of("https://payer.example.org/cds-services/" + TOKEN,
                "https://payer.example.org/cds-services/%63txToken164?q=1",
                "https://" + TOKEN + ".example.org/cds-services/x")) {
            PayerCallException failure = new PayerCallException("Hook failed: ", PayerCallPhase.HOOK, "payer",
                    URI.create(raw), response(400, HttpHeaders.of(Map.of(), (k, v) -> true)), "{}");
            PayerCallException safe = (PayerCallException) redaction.exception(failure);
            assertNotSame(failure, safe);
            if (safe.uri() != null) {
                assertFalse(safe.uri().toString().contains(TOKEN), safe.uri().toString());
                assertFalse(String.valueOf(safe.uri().getPath()).contains(TOKEN), safe.uri().getPath());
                assertFalse(String.valueOf(safe.uri().getAuthority()).contains(TOKEN), safe.uri().getAuthority());
            }
        }
        PayerCallException transport = PayerCallException.transport("failed", PayerCallPhase.HOOK, "payer",
                URI.create("https://payer.example.org/" + TOKEN), new IOException("x"));
        PayerCallException safe = (PayerCallException) redaction.exception(transport);
        assertEquals("https://payer.example.org/REDACTED", safe.uri().toString());
    }

    @Test
    void fieldsAnywhereInTheChainAreChecked() {
        PayerCallException inHeader = new PayerCallException("inner: ", PayerCallPhase.HOOK, "payer", URI_,
                response(400, HttpHeaders.of(Map.of("X-Request-Id", List.of(TOKEN)), (k, v) -> true)), "{}");
        PayerCallException inUri = PayerCallException.transport("inner", PayerCallPhase.HOOK, "payer",
                URI.create("https://payer.example.org/" + TOKEN), new IOException("x"));
        RouterException wrapper = new RouterException("could not resolve credential", inHeader);
        wrapper.addSuppressed(inUri);

        RuntimeException safe = redaction.exception(wrapper);

        assertNotSame(wrapper, safe);
        java.util.Deque<Throwable> todo = new java.util.ArrayDeque<>(List.of(safe));
        while (!todo.isEmpty()) {
            Throwable t = todo.pop();
            assertFalse(printed(t).contains(TOKEN), printed(t));
            if (t instanceof PayerCallException p) {
                assertFalse(p.responseHeaders().map().toString().contains(TOKEN));
                assertFalse(String.valueOf(p.uri()).contains(TOKEN));
                assertFalse(String.valueOf(p.responseBody()).contains(TOKEN));
            }
            if (t.getCause() != null) {
                todo.push(t.getCause());
            }
            todo.addAll(List.of(t.getSuppressed()));
        }
    }

    @Test
    void aPayerIdThatNamesTheTokenFallsBackToTheClassName() {
        PayerCallException failure = new PayerCallException("failed: ", PayerCallPhase.HOOK, "payer-" + TOKEN, URI_,
                response(400, HttpHeaders.of(Map.of(), (k, v) -> true)), "{}");

        RuntimeException safe = redaction.exception(failure);

        assertEquals(RouterException.class, safe.getClass());
        assertEquals(PayerCallException.class.getName() + ": [REDACTED]", safe.getMessage());
        assertEquals(0, safe.getStackTrace().length);
        assertNull(safe.getCause());
    }

    @Test
    void aCyclicCauseChainIsSummarisedOnce() {
        IOException inner = new IOException("inner");
        RouterException outer = new RouterException("outer", inner);
        inner.initCause(outer);

        RuntimeException safe = redaction.exception(outer);

        assertEquals("outer (cause: java.io.IOException) (cause: " + RouterException.class.getName() + ")",
                safe.getMessage());
    }

    @Test
    void aUriTheReplacementWouldBreakIsDropped() {
        PayerCallException failure = PayerCallException.transport("failed", PayerCallPhase.HOOK, "payer",
                URI.create("https://payer.example.org/a%4Ab"), new IOException("x"));

        // "%4Ab" with "4A" replaced is "%REDACTEDb", not a valid escape.
        assertNull(((PayerCallException) EhrRedaction.of("4A").exception(failure)).uri());
    }

    @Test
    void theStatusOnlyResponseCarriesNothingElse() {
        HttpHeaders headers = HttpHeaders.of(Map.of("A", List.of("b")), (k, v) -> true);
        HttpResponse<String> response = EhrRedaction.status(418, headers, URI_);

        assertEquals(418, response.statusCode());
        assertSame(headers, response.headers());
        assertEquals(URI_, response.uri());
        assertNull(response.request());
        assertNull(response.body());
        assertTrue(response.previousResponse().isEmpty());
        assertTrue(response.sslSession().isEmpty());
        assertEquals(HttpClient.Version.HTTP_1_1, response.version());
    }

    @Test
    void framesWithMissingNamesAndCleanMessagesAreStillChecked() {
        IOException error = new IOException("clean");
        error.setStackTrace(new StackTraceElement[] {new StackTraceElement("a." + TOKEN, "run", null, 3)});

        Exception safe = ExchangeSender.safeError(error, TOKEN, false);

        assertNotSame(error, safe);
        assertEquals("a.[REDACTED]", safe.getStackTrace()[0].getClassName());
        assertNull(safe.getStackTrace()[0].getFileName());
    }

    @Test
    void bodyAndPayerFieldsDeepInTheChainAreChecked() {
        PayerCallException inBody = new PayerCallException("inner: ", PayerCallPhase.HOOK, "payer", URI_,
                response(400, HttpHeaders.of(Map.of(), (k, v) -> true)), "x");
        PayerCallException inPayer = PayerCallException.transport("inner", PayerCallPhase.HOOK, TOKEN, URI_,
                new IOException("x"));
        assertFalse(ExchangeSender.mentions(new RouterException("w", inBody), TOKEN));
        assertTrue(ExchangeSender.mentions(new RouterException("w", inPayer), TOKEN));
        PayerCallException bodyShows = new PayerCallException("inner: ", PayerCallPhase.HOOK, "payer", URI_,
                response(400, HttpHeaders.of(Map.of(), (k, v) -> true)), TOKEN);
        assertTrue(ExchangeSender.fieldsShow(bodyShows, TOKEN));
    }

    private RuntimeException assertCopy(RuntimeException error, Class<?> kind) {
        RuntimeException safe = redaction.exception(error);
        assertNotSame(error, safe);
        assertEquals(kind, safe.getClass());
        assertNull(safe.getCause());
        assertEquals(0, safe.getSuppressed().length);
        assertFalse(printed(safe).contains(TOKEN), printed(safe));
        assertEquals(error.getStackTrace().length, safe.getStackTrace().length);
        if (safe instanceof PayerCallException failure) {
            assertFalse(String.valueOf(failure.responseBody()).contains(TOKEN));
            assertFalse(failure.responseHeaders().map().toString().contains(TOKEN));
        }
        return safe;
    }

    private static String printed(Throwable error) {
        StringWriter out = new StringWriter();
        error.printStackTrace(new PrintWriter(out));
        return out.toString();
    }

    private static HttpResponse<String> response(int status, HttpHeaders headers) {
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return null; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return headers; }
            @Override public String body() { return null; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return URI_; }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }
}
