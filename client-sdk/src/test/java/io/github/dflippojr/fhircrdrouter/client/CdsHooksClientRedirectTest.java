package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.FailingHttpClient;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.client.testsupport.UnroutedGuard;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The https rule (#156) is checked on the record's URLs only, so an {@link HttpClient} that follows
 * redirects would let a payer send the request somewhere unchecked: an https payer answering 307 with an
 * {@code http://} location gets the POST, credentials included, resent in cleartext by the JDK. CDS Hooks
 * 2.0, Security and Safety (https://cds-hooks.hl7.org/2.0/#security-and-safety) requires TLS for every
 * exchange, so a client whose redirect policy is not {@code NEVER} is refused before anything is read or
 * sent. The redirect target here is a second loopback server, which records whatever reaches it.
 */
class CdsHooksClientRedirectTest {

    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "i", Map.of(), null);

    private final List<String> resolved = new CopyOnWriteArrayList<>();
    private final AtomicInteger redirects = new AtomicInteger();
    /** The hand-rolled server's answer to a path no context matched, so a request no route expects still fails. */
    private static final Reply NOT_FOUND = new Reply(404, "<h1>404 Not Found</h1>No context found for request",
            Map.of("Content-Type", List.of("text/html")));

    private LoopbackPayer target;
    private LoopbackPayer redirecting;

    @BeforeEach
    void startServers() {
        target = new LoopbackPayer();
        target.otherwise(request -> NOT_FOUND);
        redirecting = new LoopbackPayer();
        redirecting.otherwise(request -> {
            redirects.incrementAndGet();
            return Reply.empty(307).withHeader("Location", target.origin() + request.rawPath());
        });
    }

    @AfterEach
    void stopServers() {
        try {
            UnroutedGuard.assertUnroutedIsNotFound(target);
        } finally {
            try {
                redirecting.close();
            } finally {
                target.close();
            }
        }
    }

    @ParameterizedTest
    @EnumSource(value = Redirect.class, names = {"NORMAL", "ALWAYS"})
    void redirectFollowingClientIsRefusedBeforeAnyRequest(Redirect policy) {
        HttpClient http = HttpClient.newBuilder().followRedirects(policy).build();

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new CdsHooksClient(http, recordingCredentials()).callHook(record(), "svc", REQUEST));

        assertTrue(e.getMessage().contains("redirect"), e.getMessage());
        assertEquals(0, redirects.get(), "request sent to the payer");
        assertEquals(List.of(), target.received(), "request followed to the redirect target");
        assertEquals(List.of(), resolved, "credentials resolved");
    }

    @ParameterizedTest
    @EnumSource(value = Redirect.class, names = {"NORMAL", "ALWAYS"})
    void everyConstructorRefusesARedirectFollowingClient(Redirect policy) {
        HttpClient http = new FailingHttpClient(policy);

        assertThrows(IllegalArgumentException.class, () -> new CdsHooksClient(http, recordingCredentials()));
        assertThrows(IllegalArgumentException.class, () -> new CdsHooksClient(http, recordingCredentials(), null));
        assertEquals(List.of(), resolved);
    }

    @Test
    void neverRedirectClientReportsTheRedirectWithoutFollowingIt() {
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), recordingCredentials());

        PayerCallException e = assertThrows(PayerCallException.class, () -> client.callHook(record(), "svc", REQUEST));

        assertEquals(307, e.statusCode().orElseThrow());
        assertEquals(1, redirects.get());
        assertEquals(List.of(), target.received(), "request followed to the redirect target");
    }

    private ConnectionRecord record() {
        return TestRecords.forAuth(AuthType.API_KEY, redirecting.url("/r4")).payerId("PAYER-REDIRECT")
                .environment(Environment.PRODUCTION).build();
    }

    private CredentialProvider recordingCredentials() {
        return new CredentialProvider() {
            @Override
            public Optional<String> resolve(String credentialRef) {
                resolved.add(credentialRef);
                return Optional.of("s3cret");
            }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }
}
