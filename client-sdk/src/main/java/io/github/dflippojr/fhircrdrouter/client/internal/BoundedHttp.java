package io.github.dflippojr.fhircrdrouter.client.internal;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * The SDK's HTTP transport for one attempt, with two bounds: the request's timeout covers the body as well as
 * the headers, and the body has a size limit. It reads no per-call context and reports to no listener;
 * {@link ExchangeSender} wraps it with the listener reporting.
 */
final class BoundedHttp {
    private BoundedHttp() { }

    /**
     * Sends {@code request} and reads its body as a string. The request's timeout bounds the whole exchange,
     * body included: the JDK's own timeout stops once the response headers arrive, so on its own a slow body
     * could outlast it. A body longer than {@code limit} bytes fails with an {@link IOException} instead of
     * being buffered.
     */
    static HttpResponse<String> send(HttpClient client, HttpRequest request, long limit)
            throws IOException, InterruptedException {
        return await(client.sendAsync(request, boundedString(limit)), request.timeout().orElse(null));
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
}
