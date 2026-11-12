package io.github.dflippojr.fhircrdrouter.client.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
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
                report(listener, new PayerExchange(phase, record.payerId(), record.environment(),
                        request.method(), request.uri(), attempt, startedAt, elapsed,
                        response == null ? OptionalInt.empty() : OptionalInt.of(response.statusCode()),
                        safeHeaders(request.headers(), true),
                        response == null ? HttpHeaders.of(Map.of(), (k, v) -> true) : safeHeaders(response.headers(), false),
                        switch (phase) {
                            case TOKEN -> null;
                            case HOOK -> hook.body();
                            case DISCOVERY -> body;
                        },
                        response == null ? null : safeBody(phase, response.body(), hook), error));
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

    private static HttpHeaders safeHeaders(HttpHeaders headers, boolean request) {
        Map<String, List<String>> safe = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.map().forEach((name, values) -> {
            if (request && name.equalsIgnoreCase("Authorization")) {
                safe.put(name, values.stream().map(ExchangeSender::redactAuthorization).toList());
            } else if (!name.equalsIgnoreCase("Set-Cookie")) {
                safe.put(name, values);
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
     * Passing the Access Token to the CDS Service</a>), with {@link EchoedCredentials#MARKER}, along with any
     * literal or standard JSON-escaped copy of the token in the body (#164). Everything else is kept. A
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
        String secret = token.isTextual() ? token.asText() : null;
        return new HookBody(redactToken(json.toString(), secret), secret);
    }

    /** {@code text} with {@code token} removed, both as is and as it reads escaped inside a JSON string. */
    private static String redactToken(String text, String token) {
        if (token == null || token.isEmpty()) {
            return text;
        }
        String escaped = MAPPER.getNodeFactory().textNode(token).toString();
        return EchoedCredentials.redact(text, token, escaped.substring(1, escaped.length() - 1));
    }

    private static String safeBody(PayerCallPhase phase, String body, HookBody hook) {
        if (phase == PayerCallPhase.HOOK) {
            // A payer that echoes the EHR token back must not leak it into the listener either. If the
            // request could not be read, the token is unknown, so the response cannot be checked: omit it.
            return hook.readable() ? redactToken(body, hook.accessToken()) : null;
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
