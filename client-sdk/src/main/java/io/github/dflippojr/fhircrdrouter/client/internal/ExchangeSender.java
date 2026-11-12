package io.github.dflippojr.fhircrdrouter.client.internal;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PayerExchange;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import javax.net.ssl.SSLSession;

/** Shared SDK implementation detail for payer and OAuth2 HTTP attempts. */
public final class ExchangeSender {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** Reads decimals exactly, so a redacted hook body keeps every number as it was sent. */
    private static final ObjectMapper EXACT = JsonMapper.builder()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            // A body Jackson would read only in part (trailing text, a repeated key) is not JSON here.
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .nodeFactory(JsonNodeFactory.withExactBigDecimals(true)).build();

    private ExchangeSender() { }

    /**
     * Sends one attempt and reads its body as a string. The request's timeout bounds the whole exchange,
     * body included: the JDK's own timeout stops once the response headers arrive, so on its own a slow
     * body could outlast it. A body longer than
     * {@link CdsHooksClient#MAX_RESPONSE_BYTES} fails with an {@link IOException} instead of being buffered.
     */
    public static HttpResponse<String> send(HttpClient client, HttpRequest request, String body,
                                            ConnectionRecord record, PayerCallPhase phase, int attempt,
                                            PayerExchangeListener listener) throws IOException, InterruptedException {
        Instant startedAt = Instant.now();
        long start = System.nanoTime();
        HttpResponse<String> response = null;
        Exception error = null;
        Redaction redaction = null;
        try {
            response = await(client.sendAsync(request, boundedString(CdsHooksClient.MAX_RESPONSE_BYTES)),
                    request.timeout().orElse(null));
            return response;
        } catch (IOException | InterruptedException e) {
            // A transport error can quote what the payer sent; neither the caller nor a listener keeps the
            // EHR token from it, in any phase (#164).
            redaction = Redaction.of(phase, body);
            error = safeError(e, redaction.token(), redaction.unreadable());
            if (error instanceof InterruptedException interrupted) {
                throw interrupted;
            }
            throw (IOException) error;
        } finally {
            Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
            if (listener != PayerExchangeListener.NOOP) {
                Redaction r = redaction == null ? Redaction.of(phase, body) : redaction;
                String token = r.token();
                report(listener, checked(new PayerExchange(phase, record.payerId(), record.environment(),
                        request.method(), request.uri(), attempt, startedAt, elapsed,
                        response == null ? OptionalInt.empty() : OptionalInt.of(response.statusCode()),
                        safeHeaders(request.headers(), true, token),
                        response == null || r.unreadable() ? HttpHeaders.of(Map.of(), (k, v) -> true)
                                : safeHeaders(response.headers(), false, token),
                        switch (phase) {
                            case TOKEN -> null;
                            case HOOK -> r.hook().body();
                            case DISCOVERY -> redactResponse(body, token);
                        },
                        response == null || r.unreadable() ? null : safeBody(phase, response.body(), token),
                        error), token));
            }
        }
    }

    /**
     * What one attempt redacts: the call's EHR token from {@link EhrRedaction#current()}, or, for a HOOK
     * attempt sent outside a call's context, the token in its own body. {@code unreadable} means a HOOK
     * body that could not be read with no token known, so nothing from the payer can be checked.
     */
    private record Redaction(String token, boolean unreadable, HookBody hook) {
        static Redaction of(PayerCallPhase phase, String body) {
            String known = EhrRedaction.current().token();
            if (phase != PayerCallPhase.HOOK) {
                return new Redaction(known, false, null);
            }
            HookBody hook = redactRequest(body, known);
            return new Redaction(hook.accessToken(), !hook.readable(), hook);
        }
    }

    /**
     * The last check before a listener sees {@code exchange}: everything above redacts each field, and if
     * the token still shows in its string form or its error chain anyway, it is not delivered (null).
     */
    private static PayerExchange checked(PayerExchange exchange, String token) {
        if (token == null) {
            return exchange;
        }
        boolean shows = shows(exchange.toString(), token) || uriShows(exchange.uri(), token)
                || exchange.error() != null && mentions(exchange.error(), token);
        return shows ? null : exchange;
    }

    private static HttpResponse<String> await(CompletableFuture<HttpResponse<String>> future, Duration deadline)
            throws IOException, InterruptedException {
        try {
            return deadline == null ? future.get() : future.get(deadline.toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new HttpTimeoutException("response not received within " + deadline);
        } catch (InterruptedException e) {
            future.cancel(true);
            throw e;
        } catch (ExecutionException e) {
            if (e.getCause() instanceof IOException io) {
                throw io;
            }
            throw new IOException(e.getCause());
        }
    }

    /** {@link HttpResponse.BodyHandlers#ofString()}, so its charset handling, with a size limit. */
    private static HttpResponse.BodyHandler<String> boundedString(long limit) {
        return info -> new BoundedSubscriber(HttpResponse.BodyHandlers.ofString().apply(info), limit);
    }

    /** Passes the body through until it exceeds {@code limit} bytes, then cancels the stream and fails. */
    private static final class BoundedSubscriber implements HttpResponse.BodySubscriber<String> {
        private final HttpResponse.BodySubscriber<String> delegate;
        private final long limit;
        private Flow.Subscription subscription;
        private long received;
        private boolean exceeded;

        BoundedSubscriber(HttpResponse.BodySubscriber<String> delegate, long limit) {
            this.delegate = delegate;
            this.limit = limit;
        }

        @Override
        public CompletionStage<String> getBody() {
            return delegate.getBody();
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            delegate.onSubscribe(subscription);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (exceeded) {
                return;
            }
            for (ByteBuffer item : items) {
                received += item.remaining();
            }
            if (received > limit) {
                exceeded = true;
                subscription.cancel();
                delegate.onError(new IOException("response body is larger than " + limit + " bytes"));
                return;
            }
            delegate.onNext(items);
        }

        @Override
        public void onError(Throwable throwable) {
            if (!exceeded) {
                delegate.onError(throwable);
            }
        }

        @Override
        public void onComplete() {
            if (!exceeded) {
                delegate.onComplete();
            }
        }
    }

    private static void report(PayerExchangeListener listener, PayerExchange exchange) {
        if (exchange == null) {
            return;
        }
        try {
            listener.onExchange(exchange);
        } catch (Exception ignored) {
            // Observability must never change the call's result, including transport failures.
        }
    }

    /**
     * {@code response} as a {@link io.github.dflippojr.fhircrdrouter.client.PayerCallException} may keep it,
     * for a HOOK call that sent {@code hookBody}: the EHR token is removed from its header names and values,
     * and its body is {@code body} with the token removed as for a listener (#164). A request body that
     * cannot be read leaves the token unknown, so the headers become empty and the body null.
     */
    public static SafeFailure safeHookFailure(HttpResponse<String> response, String body, String hookBody) {
        HookBody hook = redactRequest(hookBody, EhrRedaction.current().token());
        if (!hook.readable()) {
            return new SafeFailure(withHeaders(response, HttpHeaders.of(Map.of(), (k, v) -> true)), null);
        }
        String token = hook.accessToken();
        if (token == null) {
            return new SafeFailure(response, body);
        }
        Map<String, List<String>> safe = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        response.headers().map().forEach((name, values) -> putRedacted(safe, name, values, token));
        return new SafeFailure(withHeaders(response, HttpHeaders.of(safe, (k, v) -> true)), redactResponse(body, token));
    }

    /** A failed response with sanitised headers, and its sanitised body. */
    public record SafeFailure(HttpResponse<String> response, String body) { }

    private static HttpResponse<String> withHeaders(HttpResponse<String> response, HttpHeaders headers) {
        return new HttpResponse<>() {
            @Override public int statusCode() { return response.statusCode(); }
            @Override public HttpRequest request() { return response.request(); }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return headers; }
            @Override public String body() { return null; }
            @Override public Optional<SSLSession> sslSession() { return response.sslSession(); }
            @Override public URI uri() { return response.uri(); }
            @Override public HttpClient.Version version() { return response.version(); }
        };
    }

    /** Redacts request {@code Authorization}, drops {@code Set-Cookie}, and removes {@code token} from names and values. */
    private static HttpHeaders safeHeaders(HttpHeaders headers, boolean request, String token) {
        Map<String, List<String>> safe = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.map().forEach((name, values) -> {
            if (request && name.equalsIgnoreCase("Authorization")) {
                safe.put(name, values.stream().map(ExchangeSender::redactAuthorization).toList());
            } else if (!name.equalsIgnoreCase("Set-Cookie")) {
                putRedacted(safe, name, values, token);
            }
        });
        return HttpHeaders.of(safe, (k, v) -> true);
    }

    /** Adds a header with {@code token} removed from its name and values; names that then collide merge. */
    static void putRedacted(Map<String, List<String>> headers, String name, List<String> values, String token) {
        headers.merge(EchoedCredentials.redact(name, token),
                values.stream().map(value -> EchoedCredentials.redact(value, token)).toList(),
                (a, b) -> Stream.concat(a.stream(), b.stream()).toList());
    }

    private static String redactAuthorization(String value) {
        int space = value.indexOf(' ');
        return space > 0 ? value.substring(0, space) + " [REDACTED]" : "[REDACTED]";
    }

    /**
     * A HOOK request body as a listener sees it, and the EHR access token it hid ({@code null} if none).
     * {@code readable} is false when the body could not be read, so its token, if any, is unknown.
     */
    record HookBody(String body, String accessToken, boolean readable) {
        static final HookBody UNREADABLE = new HookBody(null, null, false);

        HookBody(String body, String accessToken) {
            this(body, accessToken, true);
        }
    }

    /**
     * Replaces {@code /fhirAuthorization/access_token}, the EHR's live FHIR token
     * (<a href="https://cds-hooks.hl7.org/2.0/#passing-the-access-token-to-the-cds-service">CDS Hooks 2.0,
     * Passing the Access Token to the CDS Service</a>), with {@link EchoedCredentials#MARKER}, along with the
     * token wherever it appears in another decoded string value or key (#164). Everything else is kept. A
     * body that cannot be read as JSON (not JSON, or past Jackson's read limits) is {@link HookBody#UNREADABLE}:
     * it cannot be checked, so it and the response are omitted.
     */
    static HookBody redactFhirAuthorization(String body) {
        return redactRequest(body, null);
    }

    /**
     * {@link #redactFhirAuthorization} with {@code known}, the call's token, redacted as well; when it is
     * known, a body that cannot be read is null but still readable, since the token to look for is known.
     */
    static HookBody redactRequest(String body, String known) {
        if (body == null) {
            return new HookBody(null, known);
        }
        JsonNode json;
        try {
            json = EXACT.readTree(body);
        } catch (IOException e) {
            return known == null ? HookBody.UNREADABLE : new HookBody(null, known);
        }
        String own = null;
        boolean changed = false;
        if (json.get("fhirAuthorization") instanceof ObjectNode auth && auth.has("access_token")) {
            JsonNode token = auth.get("access_token");
            own = token.isTextual() && !token.asText().isEmpty() ? token.asText() : null;
            auth.put("access_token", EchoedCredentials.MARKER);
            changed = true;
        }
        String secret = known != null ? known : own;
        if (secret == null) {
            return new HookBody(changed ? json.toString() : body, null);
        }
        changed |= scrub(json, secret) != null;
        if (own != null && !own.equals(secret)) {
            changed |= scrub(json, own) != null;
        }
        String safe = changed ? json.toString() : body;
        // Re-serialising can put characters next to each other that were apart in the decoded strings; a
        // body that still shows the token, as is or decoded, is not delivered.
        boolean survives = shows(safe, secret) || own != null && shows(safe, own);
        return new HookBody(survives ? null : safe, secret);
    }

    /**
     * Replaces {@code token} with {@link EchoedCredentials#MARKER} in every string value and key of
     * {@code node}, compared after JSON decoding, so no escape spelling hides it. Containers change in
     * place. Returns the replacement node, or null if nothing changed.
     */
    private static JsonNode scrub(JsonNode node, String token) {
        if (node.isTextual()) {
            String text = node.asText();
            return text.contains(token) ? TextNode.valueOf(text.replace(token, EchoedCredentials.MARKER)) : null;
        }
        boolean changed = false;
        if (node instanceof ArrayNode array) {
            for (int i = 0; i < array.size(); i++) {
                JsonNode safe = scrub(array.get(i), token);
                if (safe != null) {
                    array.set(i, safe);
                    changed = true;
                }
            }
        } else if (node instanceof ObjectNode object) {
            Map<String, JsonNode> fields = new LinkedHashMap<>();
            for (Map.Entry<String, JsonNode> field : object.properties()) {
                JsonNode safe = scrub(field.getValue(), token);
                String name = field.getKey().replace(token, EchoedCredentials.MARKER);
                changed |= safe != null || !name.equals(field.getKey());
                fields.put(name, safe == null ? field.getValue() : safe);
            }
            if (changed) {
                object.removeAll();
                object.setAll(fields);
            }
        }
        return changed ? node : null;
    }

    /**
     * A HOOK response body with {@code token} removed. A JSON body has it removed from every decoded string
     * value and key, and is re-serialised only if one changed. Any other body has the raw and JSON-escaped
     * spellings replaced; if a loose JSON decoding of what is left still shows the token, it is omitted.
     */
    static String redactResponse(String body, String token) {
        if (token == null || body == null) {
            return body;
        }
        String safe;
        try {
            JsonNode json = EXACT.readTree(body);
            JsonNode scrubbed = scrub(json, token);
            safe = scrubbed == null ? body : scrubbed.toString();
        } catch (IOException notJson) {
            safe = redactToken(body, token);
        }
        // Whatever path ran, a body that still decodes to the token is not delivered.
        return shows(safe, token) ? null : safe;
    }

    /**
     * {@code error} with the EHR token kept out of its diagnostics. A message can quote what the payer sent
     * (a malformed status line, or a parser quoting the body, say), so if any message, stack frame or
     * {@link PayerCallException} field of any cause or suppressed exception in the chain shows the token, or the token is unknown because the request could not be
     * read, this returns a copy of the same kind ({@link HttpConnectTimeoutException},
     * {@link HttpTimeoutException}, {@link InterruptedException}, {@link RuntimeException}, otherwise
     * {@link IOException}) whose
     * message names the original class, with the token removed, the original stack trace (any frame naming
     * the token redacted), and no cause or
     * suppressed exceptions. Otherwise it returns {@code error} itself.
     */
    public static Exception safeError(Exception error, String token, boolean unreadable) {
        if (error == null || !unreadable && (token == null || !mentions(error, token))) {
            return error;
        }
        String message = unreadable ? "[message omitted]" : redactToken(String.valueOf(error.getMessage()), token);
        if (!unreadable && shows(message, token)) {
            message = EchoedCredentials.MARKER;
        }
        message = error.getClass().getName() + ": " + message;
        Exception safe;
        if (error instanceof HttpConnectTimeoutException) {
            safe = new HttpConnectTimeoutException(message);
        } else if (error instanceof HttpTimeoutException) {
            safe = new HttpTimeoutException(message);
        } else if (error instanceof InterruptedException) {
            safe = new InterruptedException(message);
        } else if (error instanceof RuntimeException) {
            safe = new RuntimeException(message);
        } else {
            safe = new IOException(message);
        }
        safe.setStackTrace(safeFrames(error.getStackTrace(), token));
        return safe;
    }

    /** Whether a {@link PayerCallException}'s own fields (body, kept headers, URI, payer) show {@code token}. */
    static boolean fieldsShow(PayerCallException failure, String token) {
        return failure.responseBody() != null && shows(failure.responseBody(), token)
                || shows(failure.responseHeaders().map().toString(), token)
                || uriShows(failure.uri(), token)
                || shows(String.valueOf(failure.payerId()), token);
    }

    /** Whether {@code uri} shows {@code token}, as written or percent-decoded. */
    static boolean uriShows(URI uri, String token) {
        return uri != null && (shows(uri.toString(), token) || shows(String.valueOf(uri.getAuthority())
                + uri.getPath() + uri.getQuery() + uri.getFragment(), token));
    }

    /** {@code frames} with {@code token} removed from every class, method, file and module name. */
    static StackTraceElement[] safeFrames(StackTraceElement[] frames, String token) {
        if (token == null) {
            return frames;
        }
        StackTraceElement[] safe = frames.clone();
        for (int i = 0; i < safe.length; i++) {
            StackTraceElement f = safe[i];
            if (shows(f.toString(), token)) {
                safe[i] = new StackTraceElement(clean(f.getClassLoaderName(), token), clean(f.getModuleName(), token),
                        clean(f.getModuleVersion(), token), clean(f.getClassName(), token),
                        clean(f.getMethodName(), token), clean(f.getFileName(), token), f.getLineNumber());
            }
        }
        return safe;
    }

    private static String clean(String text, String token) {
        if (text == null) {
            return null;
        }
        String safe = redactToken(text, token);
        return shows(safe, token) ? EchoedCredentials.MARKER : safe;
    }

    static boolean mentions(Throwable error, String token) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<Throwable> todo = new ArrayDeque<>(List.of(error));
        while (!todo.isEmpty()) {
            Throwable t = todo.pop();
            if (!seen.add(t)) {
                continue;
            }
            if (shows(String.valueOf(t.getMessage()), token) || shows(t.toString(), token)) {
                return true;
            }
            for (StackTraceElement frame : t.getStackTrace()) {
                if (shows(frame.toString(), token)) {
                    return true;
                }
            }
            if (t instanceof PayerCallException failure && fieldsShow(failure, token)) {
                return true;
            }
            if (t.getCause() != null) {
                todo.push(t.getCause());
            }
            todo.addAll(List.of(t.getSuppressed()));
        }
        return false;
    }

    /** Whether {@code text} shows {@code token} as is or once its JSON escapes are decoded. */
    static boolean shows(String text, String token) {
        return text.contains(token) || looselyDecoded(text).contains(token);
    }

    /** {@code text} with JSON string escapes decoded wherever they appear; unknown escapes are kept. */
    static String looselyDecoded(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c != '\\' || i + 1 == text.length()) {
                out.append(c);
                continue;
            }
            char next = text.charAt(i + 1);
            int simple = "\"\\/bfnrt".indexOf(next);
            if (simple >= 0) {
                out.append("\"\\/\b\f\n\r\t".charAt(simple));
                i++;
            } else if (next == 'u' && i + 6 <= text.length() && isHex(text, i + 2, i + 6)) {
                out.append((char) Integer.parseInt(text.substring(i + 2, i + 6), 16));
                i += 5;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static boolean isHex(String text, int from, int to) {
        for (int i = from; i < to; i++) {
            if (Character.digit(text.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * {@code text} with {@code token} removed: as is, as Jackson escapes it inside a JSON string, and that
     * escaped form with {@code /} written as {@code \/}. Longest first, so the raw token never consumes
     * only the start of an escaped spelling (a token ending in a backslash, say) and leaves a stray tail.
     */
    static String redactToken(String text, String token) {
        String quoted = MAPPER.getNodeFactory().textNode(token).toString();
        String escaped = quoted.substring(1, quoted.length() - 1);
        String[] spellings = new LinkedHashSet<>(List.of(escaped.replace("/", "\\/"), escaped, token))
                .stream().sorted(Comparator.comparingInt(String::length).reversed()).toArray(String[]::new);
        return EchoedCredentials.redact(text, spellings);
    }

    private static String safeBody(PayerCallPhase phase, String body, String token) {
        if (phase != PayerCallPhase.TOKEN) {
            // A payer that echoes the EHR token back must not leak it into the listener either.
            return redactResponse(body, token);
        }
        return redactResponse(tokenSummary(body), token);
    }

    /** A TOKEN response reduced to its scalar {@code token_type}, {@code expires_in} and {@code scope}. */
    private static String tokenSummary(String body) {
        var safe = MAPPER.createObjectNode();
        try {
            JsonNode json = MAPPER.readTree(body);
            for (String field : List.of("token_type", "expires_in", "scope")) {
                if (json != null && json.has(field) && json.get(field).isValueNode()) {
                    safe.set(field, json.get(field));
                }
            }
        } catch (IOException ignored) {
            // Never expose raw token responses or parser exceptions containing their source.
        }
        return safe.toString();
    }
}
