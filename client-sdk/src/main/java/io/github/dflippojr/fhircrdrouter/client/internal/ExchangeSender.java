package io.github.dflippojr.fhircrdrouter.client.internal;

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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Shared SDK implementation detail for payer and OAuth2 HTTP attempts. What a listener is shown is redacted
 * by {@link SecretScrubber}, under the token this class reads from the call's {@link EhrRedaction} context.
 */
public final class ExchangeSender {
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
            // Under an EHR token the error is always a fresh copy with no cause, whatever its text says (#164).
            error = redaction.token() != null || redaction.unreadable()
                    ? SecretScrubber.freshError(e, redaction.token(), redaction.unreadable()) : e;
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
                        SecretScrubber.safeHeaders(request.headers(), true, token),
                        response == null || r.unreadable() ? HttpHeaders.of(Map.of(), (k, v) -> true)
                                : SecretScrubber.safeHeaders(response.headers(), false, token),
                        switch (phase) {
                            case TOKEN -> null;
                            case HOOK -> r.hook().body();
                            case DISCOVERY -> SecretScrubber.redactResponse(body, token);
                        },
                        response == null || r.unreadable() ? null
                                : SecretScrubber.safeBody(phase, response.body(), token),
                        error), token));
            }
        }
    }

    /**
     * What one attempt redacts: the call's EHR token from {@link EhrRedaction#current()}, or, for a HOOK
     * attempt sent outside a call's context, the token in its own body. {@code unreadable} means a HOOK
     * body that could not be read with no token known, so nothing from the payer can be checked.
     */
    private record Redaction(String token, boolean unreadable, SecretScrubber.HookBody hook) {
        static Redaction of(PayerCallPhase phase, String body) {
            String known = EhrRedaction.current().token();
            if (phase != PayerCallPhase.HOOK) {
                return new Redaction(known, false, null);
            }
            SecretScrubber.HookBody hook = SecretScrubber.redactRequest(body, known);
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
        // Bodies, headers and the error are redacted above (the error is always a fresh copy under a token);
        // the string form and the URI are checked as a whole.
        return SecretScrubber.shows(exchange.toString(), token) || SecretScrubber.uriShows(exchange.uri(), token)
                ? null : exchange;
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
}
