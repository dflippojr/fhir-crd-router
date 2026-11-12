package io.github.dflippojr.fhircrdrouter.client.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PayerExchange;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpConnectTimeoutException;
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
import java.util.OptionalInt;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

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
        try {
            response = await(client.sendAsync(request, boundedString(CdsHooksClient.MAX_RESPONSE_BYTES)),
                    request.timeout().orElse(null));
            return response;
        } catch (IOException | InterruptedException e) {
            error = e;
            throw e;
        } finally {
            Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
            if (listener != PayerExchangeListener.NOOP) {
                HookBody hook = phase == PayerCallPhase.HOOK ? redactFhirAuthorization(body) : null;
                String token = hook == null ? null : hook.accessToken();
                boolean unreadable = hook != null && !hook.readable();
                report(listener, new PayerExchange(phase, record.payerId(), record.environment(),
                        request.method(), request.uri(), attempt, startedAt, elapsed,
                        response == null ? OptionalInt.empty() : OptionalInt.of(response.statusCode()),
                        safeHeaders(request.headers(), true, null),
                        response == null || unreadable ? HttpHeaders.of(Map.of(), (k, v) -> true)
                                : safeHeaders(response.headers(), false, token),
                        switch (phase) {
                            case TOKEN -> null;
                            case HOOK -> hook.body();
                            case DISCOVERY -> body;
                        },
                        response == null ? null : safeBody(phase, response.body(), hook),
                        safeError(error, token, unreadable)));
            }
        }
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
        try {
            listener.onExchange(exchange);
        } catch (Exception ignored) {
            // Observability must never change the call's result, including transport failures.
        }
    }

    /** Redacts request {@code Authorization}, drops {@code Set-Cookie}, and removes {@code token} from names and values. */
    private static HttpHeaders safeHeaders(HttpHeaders headers, boolean request, String token) {
        Map<String, List<String>> safe = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.map().forEach((name, values) -> {
            if (request && name.equalsIgnoreCase("Authorization")) {
                safe.put(name, values.stream().map(ExchangeSender::redactAuthorization).toList());
            } else if (!name.equalsIgnoreCase("Set-Cookie")) {
                safe.merge(EchoedCredentials.redact(name, token),
                        values.stream().map(value -> EchoedCredentials.redact(value, token)).toList(),
                        (a, b) -> Stream.concat(a.stream(), b.stream()).toList());
            }
        });
        return HttpHeaders.of(safe, (k, v) -> true);
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
        if (body == null) {
            return new HookBody(null, null);
        }
        JsonNode json;
        try {
            json = EXACT.readTree(body);
        } catch (IOException e) {
            return HookBody.UNREADABLE;
        }
        if (!(json.get("fhirAuthorization") instanceof ObjectNode auth) || !auth.has("access_token")) {
            return new HookBody(body, null);
        }
        JsonNode token = auth.get("access_token");
        auth.put("access_token", EchoedCredentials.MARKER);
        String secret = token.isTextual() && !token.asText().isEmpty() ? token.asText() : null;
        if (secret != null) {
            scrub(json, secret);
        }
        return new HookBody(json.toString(), secret);
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
    private static String redactResponse(String body, String token) {
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
        return looselyDecoded(safe).contains(token) ? null : safe;
    }

    /**
     * The transport error as a listener sees it. A message can quote what the payer sent (a malformed
     * status line, say), so if any message in the chain shows the token, or the token is unknown because
     * the request could not be read, the listener gets a copy of the same kind with the token removed and
     * no cause. The caller still gets the original.
     */
    static Exception safeError(Exception error, String token, boolean unreadable) {
        if (error == null || !unreadable && (token == null || !mentions(error, token))) {
            return error;
        }
        String message = unreadable ? "[message omitted]" : redactToken(String.valueOf(error.getMessage()), token);
        if (!unreadable && looselyDecoded(message).contains(token)) {
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
        } else {
            safe = new IOException(message);
        }
        safe.setStackTrace(error.getStackTrace());
        return safe;
    }

    private static boolean mentions(Throwable error, String token) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<Throwable> todo = new ArrayDeque<>(List.of(error));
        while (!todo.isEmpty()) {
            Throwable t = todo.pop();
            if (!seen.add(t)) {
                continue;
            }
            if (looselyDecoded(String.valueOf(t.getMessage())).contains(token)
                    || looselyDecoded(t.toString()).contains(token)) {
                return true;
            }
            if (t.getCause() != null) {
                todo.push(t.getCause());
            }
            todo.addAll(List.of(t.getSuppressed()));
        }
        return false;
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
    private static String redactToken(String text, String token) {
        String quoted = MAPPER.getNodeFactory().textNode(token).toString();
        String escaped = quoted.substring(1, quoted.length() - 1);
        String[] spellings = new LinkedHashSet<>(List.of(escaped.replace("/", "\\/"), escaped, token))
                .stream().sorted(Comparator.comparingInt(String::length).reversed()).toArray(String[]::new);
        return EchoedCredentials.redact(text, spellings);
    }

    private static String safeBody(PayerCallPhase phase, String body, HookBody hook) {
        if (phase == PayerCallPhase.HOOK) {
            // A payer that echoes the EHR token back must not leak it into the listener either. If the
            // request could not be read, the token is unknown, so the response cannot be checked: omit it.
            return hook.readable() ? redactResponse(body, hook.accessToken()) : null;
        }
        if (phase != PayerCallPhase.TOKEN) {
            return body;
        }
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
