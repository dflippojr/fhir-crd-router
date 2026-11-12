package io.github.dflippojr.fhircrdrouter.client.internal;

import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditPersistenceException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
        return token == null ? text : ExchangeSender.clean(text, token);
    }

    /**
     * {@code error} as it may leave a call that carries an EHR token. With no token this is
     * {@code error} itself. Otherwise it is always a fresh exception, whether or not the original's text
     * shows the token, because an exception can reference the token through more than its text (a
     * parser's path back to the request it was writing, say). The copy is built only from the
     * original's message with the token removed, the class names of its causes ({@code (cause: <class>)};
     * their messages are left out), its class, and its stack frames with the token
     * removed from any frame that names it. It has <b>no cause and no suppressed exceptions</b>. Its
     * class is the original's for {@link PayerCallException} (keeping phase, payer, status,
     * {@link PayerCallException#timedOut()}, the redacted body and kept headers, and the URI with the
     * token replaced), {@link RouterException}, {@link IllegalArgumentException} and
     * {@link IllegalStateException}; any other class becomes a {@link RouterException} whose message
     * names it. A copy that would still show the token (a payer id naming it, say) becomes a
     * {@link RouterException} naming only the original class, with no stack frames. The one exception
     * returned as is: an {@link AuditPersistenceException} with no cause or suppressed exceptions, which
     * callers must receive by type and which holds only a fixed message, an operation state and ids.
     */
    public RuntimeException exception(RuntimeException error) {
        if (token == null) {
            return error;
        }
        if (error instanceof AuditPersistenceException audit && audit.getCause() == null
                && audit.getSuppressed().length == 0 && !ExchangeSender.mentions(audit, token)) {
            // Callers must see this type to stop and report audit failures, and core builds it from an
            // audit event only: a fixed message, an operation state and two ids, never a cause.
            return audit;
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
        String message = text(error.getMessage()) + causes(error);
        if (error instanceof PayerCallException failure) {
            return copy(failure);
        }
        if (error.getClass() == RouterException.class) {
            return new RouterException(message);
        }
        if (error.getClass() == IllegalArgumentException.class) {
            return new IllegalArgumentException(message);
        }
        if (error.getClass() == IllegalStateException.class) {
            return new IllegalStateException(message);
        }
        return new RouterException(error.getClass().getName() + ": " + message);
    }

    private PayerCallException copy(PayerCallException failure) {
        if (failure.statusCode().isEmpty()) {
            return PayerCallException.transport(text(failure.getMessage()) + causes(failure), failure.phase(),
                    failure.payerId(), uri(failure.uri()), failure.timedOut());
        }
        String message = String.valueOf(failure.getMessage());
        // PayerCallException is final and its message is always the prefix followed by its body.
        String body = failure.responseBody();
        String prefix = message.substring(0, message.length() - body.length());
        String safeBody = ExchangeSender.redactResponse(body, token);
        URI uri = uri(failure.uri());
        return new PayerCallException(text(prefix), failure.phase(), failure.payerId(), uri,
                status(failure.statusCode().getAsInt(), headers(failure.responseHeaders()), uri),
                safeBody == null ? EchoedCredentials.MARKER : safeBody);
    }

    /**
     * The cause chain as class names only: {@code " (cause: <class>)"} for each. Cause messages are left
     * out: a credential provider's can describe secret material, and a parser's can quote the payer.
     */
    private String causes(Throwable error) {
        StringBuilder out = new StringBuilder();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable t = error.getCause(); t != null && seen.add(t); t = t.getCause()) {
            out.append(" (cause: ").append(text(t.getClass().getName())).append(')');
        }
        return out.toString();
    }

    /**
     * {@code uri} with the token replaced by {@code REDACTED}; null if it still shows (percent-encoded,
     * say) or the replacement is not a valid URI.
     */
    private URI uri(URI uri) {
        if (!ExchangeSender.uriShows(uri, token)) {
            return uri;
        }
        URI replaced;
        try {
            replaced = URI.create(uri.toString().replace(token, "REDACTED"));
        } catch (IllegalArgumentException e) {
            return null;
        }
        return ExchangeSender.uriShows(replaced, token) ? null : replaced;
    }

    private HttpHeaders headers(HttpHeaders headers) {
        Map<String, List<String>> safe = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.map().forEach((name, values) -> ExchangeSender.putRedacted(safe, name, values, token));
        return HttpHeaders.of(safe, (k, v) -> true);
    }

    private boolean showsAnywhere(Throwable error) {
        // Every message, string form, stack frame and PayerCallException field in the cause and suppressed chain.
        return ExchangeSender.mentions(error, token);
    }

    /** A response carrying only a status and headers, which is all a {@link PayerCallException} keeps. */
    static HttpResponse<String> status(int status, HttpHeaders headers, URI uri) {
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
