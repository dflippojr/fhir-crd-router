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
    void exceptionsWithoutTheTokenPassThrough() {
        RouterException clean = new RouterException("fine", new IOException("also fine"));
        assertSame(clean, redaction.exception(clean));
        RouterException leaky = new RouterException(TOKEN);
        assertSame(leaky, EhrRedaction.NONE.exception(leaky));
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
        assertNull(withError.getCause());
        RuntimeException cleanError = new RouterException("m " + TOKEN, new AssertionError("fine"));
        assertInstanceOf(AssertionError.class, redaction.exception(cleanError).getCause());
    }

    @Test
    void payerCallExceptionsKeepTheirFields() {
        PayerCallException transport = PayerCallException.transport("failed " + TOKEN, PayerCallPhase.TOKEN, "payer",
                URI_, new IOException(TOKEN));
        PayerCallException safeTransport = (PayerCallException) assertCopy(transport, PayerCallException.class);
        assertTrue(safeTransport.statusCode().isEmpty());
        assertEquals(PayerCallPhase.TOKEN, safeTransport.phase());
        assertInstanceOf(IOException.class, safeTransport.getCause());

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

    private RuntimeException assertCopy(RuntimeException error, Class<?> kind) {
        RuntimeException safe = redaction.exception(error);
        assertNotSame(error, safe);
        assertEquals(kind, safe.getClass());
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
