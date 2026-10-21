package io.github.dflippojr.fhircrdrouter.client.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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
                report(listener, new PayerExchange(phase, record.payerId(), record.environment(),
                        request.method(), request.uri(), attempt, startedAt, elapsed,
                        response == null ? OptionalInt.empty() : OptionalInt.of(response.statusCode()),
                        safeHeaders(request.headers(), true),
                        response == null ? HttpHeaders.of(Map.of(), (k, v) -> true) : safeHeaders(response.headers(), false),
                        phase == PayerCallPhase.TOKEN ? null : body,
                        response == null ? null : safeBody(phase, response.body()), error));
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

    private static HttpResponse.BodyHandler<String> boundedString(long limit) {
        return info -> new BoundedSubscriber(HttpResponse.BodySubscribers.ofString(charset(info.headers())), limit);
    }

    /** The Content-Type charset, else UTF-8, as {@link HttpResponse.BodyHandlers#ofString()} decides it. */
    private static Charset charset(HttpHeaders headers) {
        for (String param : headers.firstValue("Content-Type").orElse("").split(";")) {
            String p = param.strip();
            if (p.regionMatches(true, 0, "charset=", 0, 8)) {
                try {
                    return Charset.forName(p.substring(8).replace("\"", ""));
                } catch (IllegalArgumentException e) {
                    return StandardCharsets.UTF_8;
                }
            }
        }
        return StandardCharsets.UTF_8;
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

    private static String safeBody(PayerCallPhase phase, String body) {
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
