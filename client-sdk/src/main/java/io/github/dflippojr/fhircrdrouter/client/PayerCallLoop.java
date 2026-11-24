package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.auth.JwtSigner;
import io.github.dflippojr.fhircrdrouter.client.auth.OAuth2TokenClient;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.client.internal.EhrRedaction;
import io.github.dflippojr.fhircrdrouter.client.internal.EndpointUrls;
import io.github.dflippojr.fhircrdrouter.client.internal.ExchangeSender;
import io.github.dflippojr.fhircrdrouter.client.internal.SecretScrubber;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.function.Supplier;

/**
 * Sends each {@link CdsHooksClient} payer call: applies the record's auth, retries an OAuth2 call once with a
 * new token after a 401, retries 429 and 503 under the opt-in {@link RetryPolicy}, and turns any other failure
 * into a {@link PayerCallException} that keeps neither the bearer credential nor the EHR token.
 */
final class PayerCallLoop {
    private final PayerExchangeListener exchangeListener;
    private final Duration requestTimeout;
    private final MtlsClients mtlsClients;
    private final CredentialLookup credentials;
    private final OAuth2TokenClient oauth2TokenClient;
    private final JwtSigner jwtSigner = new JwtSigner();
    private volatile RetryPolicy retryPolicy = RetryPolicy.NONE;

    PayerCallLoop(HttpClient httpClient, Duration requestTimeout, PayerExchangeListener exchangeListener,
                  MtlsClients mtlsClients, CredentialLookup credentials) {
        this.exchangeListener = exchangeListener;
        this.requestTimeout = requestTimeout;
        this.mtlsClients = mtlsClients;
        this.credentials = credentials;
        this.oauth2TokenClient = new OAuth2TokenClient(httpClient, requestTimeout, exchangeListener);
    }

    /** Sets the policy that calls sent after this read; {@link CdsHooksClient#retryPolicy} rejects null. */
    void retryPolicy(RetryPolicy policy) {
        this.retryPolicy = policy;
    }

    /** A new {@link FreshToken}, for a call that must not use the token cache. */
    FreshToken freshToken() {
        return new FreshToken();
    }

    /**
     * Sends a request with auth applied. For OAuth2 connections a 401 drops the
     * cached token and retries once with a fresh one, since payers can revoke
     * tokens before their advertised expiry. With a {@code freshToken} the call bypasses the cache: a 401 on
     * the token just issued is the result, so nothing is dropped and nothing is retried.
     */
    HttpResponse<String> send(ConnectionRecord record, PayerCallPhase phase, String context, String body,
                              FreshToken freshToken, Supplier<HttpRequest.Builder> requestFactory) {
        // CDS Hooks 2.0, Security and Safety (https://cds-hooks.hl7.org/2.0/#security-and-safety) requires TLS
        // for every exchange: refuse the record's URLs before any credential read, token fetch or request (#156).
        EndpointUrls.requireUsable(record);
        URI uri = requestFactory.get().build().uri();
        try {
            HttpClient client = mtlsClients.httpClientFor(record);
            RetryPolicy policy = retryPolicy;
            int attempt = 1;
            int throttleRetries = 0;
            boolean reauthenticated = false;
            Duration waited = Duration.ZERO;
            while (true) {
                Attempt sent = sendOnce(client, record, phase, body, attempt, freshToken, requestFactory);
                HttpResponse<String> response = sent.response();
                int status = response.statusCode();
                if (status / 100 == 2) {
                    return response;
                }
                if (status == 401 && record.authType().usesOAuth2Token() && freshToken == null && !reauthenticated) {
                    reauthenticated = true;
                    oauth2TokenClient.invalidate(record);
                    attempt++;
                    continue;
                }
                // A payer may echo the bearer it rejected; keep it out of the exception callers log (#195).
                // On a HOOK call it may also echo the EHR's fhirAuthorization token; remove that too (#164).
                String failed = SecretScrubber.redact(response.body(), sent.credential());
                HttpResponse<String> kept = response;
                if (phase == PayerCallPhase.HOOK) {
                    SecretScrubber.SafeFailure safe = SecretScrubber.safeHookFailure(response, failed, body,
                            EhrRedaction.current().token());
                    kept = safe.response();
                    failed = safe.body();
                }
                PayerCallException failure = new PayerCallException(context + " failed: payer returned HTTP "
                        + status + ": ", phase, record.payerId(), uri, kept, failed);
                // Retry timing comes from the payer's own response: the exception's headers may be sanitised.
                Duration wait = policy.enabled() && RetryPolicy.retryable(status)
                        && throttleRetries + 1 < policy.maxAttempts()
                        ? response.headers().firstValue("Retry-After")
                                .flatMap(v -> PayerCallException.parseRetryAfter(v, Clock.systemUTC())).orElse(null)
                        : null;
                if (wait == null || wait.compareTo(policy.maxTotalWait().minus(waited)) > 0) {
                    throw failure;
                }
                sleep(wait);
                waited = waited.plus(wait);
                throttleRetries++;
                attempt++;
            }
        } catch (IOException e) {
            throw PayerCallException.transport(context + " failed", phase, record.payerId(), uri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw PayerCallException.transport(context + " interrupted", phase, record.payerId(), uri, e);
        }
    }

    private static void sleep(Duration wait) throws InterruptedException {
        if (!wait.isZero()) {
            Thread.sleep(wait.toMillis() + (wait.toNanosPart() % 1_000_000 == 0 ? 0 : 1));
        }
    }

    /** One attempt's response, and the credential its {@code Authorization} header carried (null for none). */
    private record Attempt(HttpResponse<String> response, String credential) { }

    private Attempt sendOnce(HttpClient client, ConnectionRecord record,
                             PayerCallPhase phase, String body, int attempt, FreshToken freshToken,
                             Supplier<HttpRequest.Builder> requestFactory)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = requestFactory.get().timeout(requestTimeout);
        URI uri = builder.copy().build().uri();
        applyAuth(client, builder, uri, record, attempt, freshToken);
        HttpRequest request = builder.build();
        String credential = SecretScrubber.fromAuthorization(request.headers().firstValue("Authorization").orElse(null));
        return new Attempt(ExchangeSender.send(client, request, body, record, phase, attempt, exchangeListener),
                credential);
    }

    /** The one token of a call that bypasses the cache: exchanged on first use, then reused by its retries. */
    final class FreshToken {
        private String token;

        String get(HttpClient client, ConnectionRecord record, int attempt) {
            if (token == null) {
                token = oauth2TokenClient.exchangeFreshToken(client, record, () -> credentials.requireSecret(record), attempt);
            }
            return token;
        }
    }

    private void applyAuth(HttpClient client, HttpRequest.Builder builder, URI uri, ConnectionRecord record, int attempt,
                           FreshToken freshToken) {
        switch (record.authType()) {
            case NONE -> { /* no-op */ }
            case API_KEY -> builder.header("Authorization", "Bearer " + credentials.requireApiKey(record));
            case OAUTH2_CLIENT_CREDENTIALS, OAUTH2_PRIVATE_KEY_JWT -> builder.header("Authorization",
                    "Bearer " + (freshToken != null ? freshToken.get(client, record, attempt)
                            : oauth2TokenClient.fetchAccessToken(client, record, () -> credentials.requireSecret(record), attempt)));
            case CDS_HOOKS_JWT -> builder.header("Authorization",
                    "Bearer " + jwtSigner.cdsHooksJwt(record, PemKeys.readPrivateKey(credentials.requireSecret(record)), uri));
        }
    }
}
