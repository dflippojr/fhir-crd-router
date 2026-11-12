package io.github.dflippojr.fhircrdrouter.client.internal;

import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.core.RouterException;

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
import java.util.TreeMap;
import javax.net.ssl.SSLSession;

/**
 * The per-call redaction context for the EHR's {@code fhirAuthorization} token
 * (<a href="https://cds-hooks.hl7.org/2.0/#passing-the-access-token-to-the-cds-service">CDS Hooks 2.0,
 * Passing the Access Token to the CDS Service</a>), #164.
 *
 * <p>A hook call opens one when it starts, from the request it was given, and it stays current on the
 * calling thread until the call returns. Every exposure boundary reads it: {@link ExchangeSender} for each
 * listener exchange of every phase (HOOK, and TOKEN including a re-authentication after a 401), the
 * token client for error bodies, and {@link #exception} for each exception that leaves the SDK. All of an
 * SDK call's sends and listener callbacks run on the calling thread, so a thread-local context reaches
 * the token client without changing its API.
 */
public final class EhrRedaction {
    /** No EHR token: nothing to redact. */
    public static final EhrRedaction NONE = new EhrRedaction(null);
    private static final ThreadLocal<EhrRedaction> CURRENT = new ThreadLocal<>();

    private final String token;

    private EhrRedaction(String token) {
        this.token = token;
    }

    /** The context for {@code token}; {@link #NONE} if it is null or empty. */
    public static EhrRedaction of(String token) {
        return token == null || token.isEmpty() ? NONE : new EhrRedaction(token);
    }

    /** The context of the call running on this thread, or {@link #NONE}. */
    public static EhrRedaction current() {
        EhrRedaction current = CURRENT.get();
        return current == null ? NONE : current;
    }

    /** The token to redact, or null. */
    public String token() {
        return token;
    }

    /** Makes this the current context on this thread until the scope closes. Scopes nest. */
    public Scope open() {
        EhrRedaction previous = CURRENT.get();
        CURRENT.set(this);
        return () -> {
            if (previous == null) {
                CURRENT.remove();
            } else {
                CURRENT.set(previous);
            }
        };
    }

    /** An open context; closing it restores the one before. */
    public interface Scope extends AutoCloseable {
        @Override
        void close();
    }

    /** {@code text} with the token removed; the whole text becomes the marker if a spelling survives. */
    public String text(String text) {
        if (token == null || text == null) {
            return text;
        }
        String safe = ExchangeSender.redactToken(text, token);
        return ExchangeSender.shows(safe, token) ? EchoedCredentials.MARKER : safe;
    }

    /**
     * {@code error} as it may leave the SDK. If the token shows anywhere in it (message, cause or
     * suppressed chain, printed stack trace, or the body, headers, URI or payer of a
     * {@link PayerCallException} anywhere in that chain), this
     * returns a copy of the same class ({@link PayerCallException}, {@link RouterException},
     * {@link IllegalArgumentException}, {@link IllegalStateException}; any other class becomes a
     * {@link RouterException} whose message names it) with the token removed from its message, body,
     * headers and URI, its cause replaced by a redacted copy with no chain of its own, no suppressed exceptions,
     * and the original stack trace with the token removed from any frame that names it. Otherwise it
     * returns {@code error} itself.
     */
    public RuntimeException exception(RuntimeException error) {
        if (token == null || !showsAnywhere(error)) {
            return error;
        }
        RuntimeException safe = copy(error);
        safe.setStackTrace(ExchangeSender.safeFrames(error.getStackTrace(), token));
        if (showsAnywhere(safe)) {
            safe = new RouterException(error.getClass().getName() + ": " + EchoedCredentials.MARKER);
            safe.setStackTrace(new StackTraceElement[0]);
        }
        return safe;
    }

    private RuntimeException copy(RuntimeException error) {
        String message = text(error.getMessage());
        Throwable cause = cause(error.getCause());
        if (error instanceof PayerCallException failure) {
            return copy(failure, cause);
        }
        if (error.getClass() == RouterException.class) {
            return new RouterException(message, cause);
        }
        if (error.getClass() == IllegalArgumentException.class) {
            return new IllegalArgumentException(message, cause);
        }
        if (error.getClass() == IllegalStateException.class) {
            return new IllegalStateException(message, cause);
        }
        return new RouterException(error.getClass().getName() + ": " + message, cause);
    }

    private PayerCallException copy(PayerCallException failure, Throwable cause) {
        if (failure.statusCode().isEmpty()) {
            return PayerCallException.transport(text(failure.getMessage()), failure.phase(), failure.payerId(),
                    uri(failure.uri()), cause);
        }
        String message = String.valueOf(failure.getMessage());
        String body = failure.responseBody() == null ? "" : failure.responseBody();
        String prefix = message.endsWith(body) ? message.substring(0, message.length() - body.length()) : message;
        String safeBody = ExchangeSender.redactResponse(body, token);
        URI uri = uri(failure.uri());
        return new PayerCallException(text(prefix), failure.phase(), failure.payerId(), uri,
                status(failure.statusCode().getAsInt(), headers(failure.responseHeaders()), uri),
                safeBody == null ? EchoedCredentials.MARKER : safeBody);
    }

    /**
     * {@code uri} with the token replaced by {@code REDACTED}; if it still shows (percent-encoded, say),
     * only its scheme and host are kept, and if even the host shows it, null.
     */
    private URI uri(URI uri) {
        if (!ExchangeSender.uriShows(uri, token)) {
            return uri;
        }
        try {
            URI replaced = URI.create(uri.toString().replace(token, "REDACTED"));
            if (!ExchangeSender.uriShows(replaced, token)) {
                return replaced;
            }
            URI origin = new URI(uri.getScheme(), uri.getHost(), null, null);
            return ExchangeSender.uriShows(origin, token) ? null : origin;
        } catch (java.net.URISyntaxException | IllegalArgumentException e) {
            return null;
        }
    }

    private Throwable cause(Throwable cause) {
        if (cause == null) {
            return null;
        }
        if (cause instanceof Exception exception) {
            return ExchangeSender.safeError(exception, token, false);
        }
        return ExchangeSender.shows(printed(cause), token) ? null : cause;
    }

    private HttpHeaders headers(HttpHeaders headers) {
        Map<String, List<String>> safe = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.map().forEach((name, values) -> ExchangeSender.putRedacted(safe, name, values, token));
        return HttpHeaders.of(safe, (k, v) -> true);
    }

    private boolean showsAnywhere(Throwable error) {
        // The printed trace, plus every PayerCallException field anywhere in the cause and suppressed chain.
        return ExchangeSender.shows(printed(error), token) || ExchangeSender.mentions(error, token);
    }

    private static String printed(Throwable error) {
        StringWriter out = new StringWriter();
        error.printStackTrace(new PrintWriter(out));
        return out.toString();
    }

    /** A response carrying only a status and headers, which is all a {@link PayerCallException} keeps. */
    private static HttpResponse<String> status(int status, HttpHeaders headers, URI uri) {
        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public HttpRequest request() { return null; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return headers; }
            @Override public String body() { return null; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return uri; }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }
}
