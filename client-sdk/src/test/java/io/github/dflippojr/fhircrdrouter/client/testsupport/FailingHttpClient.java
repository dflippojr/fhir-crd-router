package io.github.dflippojr.fhircrdrouter.client.testsupport;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static org.junit.jupiter.api.Assertions.fail;

/** An HttpClient that fails the test if anything is sent through it. */
public final class FailingHttpClient extends HttpClient {
    private final Redirect redirect;

    public FailingHttpClient() {
        this(Redirect.NEVER);
    }

    /** Reports {@code redirect} from {@link #followRedirects()}, to test clients that would follow one. */
    public FailingHttpClient(Redirect redirect) {
        this.redirect = redirect;
    }

    @Override public Optional<CookieHandler> cookieHandler() { return Optional.empty(); }
    @Override public Optional<Duration> connectTimeout() { return Optional.empty(); }
    @Override public Redirect followRedirects() { return redirect; }
    @Override public Optional<ProxySelector> proxy() { return Optional.empty(); }
    @Override public SSLContext sslContext() { return null; }
    @Override public SSLParameters sslParameters() { return new SSLParameters(); }
    @Override public Optional<Authenticator> authenticator() { return Optional.empty(); }
    @Override public Version version() { return Version.HTTP_1_1; }
    @Override public Optional<Executor> executor() { return Optional.empty(); }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        return fail("HttpClient.send called for " + request.uri());
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                                                            HttpResponse.BodyHandler<T> handler) {
        return fail("HttpClient.sendAsync called for " + request.uri());
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                                                            HttpResponse.BodyHandler<T> handler,
                                                            HttpResponse.PushPromiseHandler<T> push) {
        return fail("HttpClient.sendAsync called for " + request.uri());
    }
}
