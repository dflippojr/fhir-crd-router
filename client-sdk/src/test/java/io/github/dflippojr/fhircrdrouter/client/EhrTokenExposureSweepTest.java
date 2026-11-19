package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest.FhirAuthorization;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Drives every HOOK-call outcome, of every phase, through one check: the EHR's {@code fhirAuthorization}
 * token appears in no listener exchange (any phase, any field, its error chain) and in no exception that
 * leaves the SDK (message, fields, cause and suppressed chain, printed stack trace) (#164).
 */
class EhrTokenExposureSweepTest {
    /** Letters and digits only, so a parser quotes it whole. */
    private static final String TOKEN = "SweepEhrToken164abcdef";
    private static final String EHR = "https://ehr.example.org/fhir";
    private static final String OK = "{\"cards\":[]}";

    private final List<PayerExchange> exchanges = new CopyOnWriteArrayList<>();
    /** The hand-rolled server's answer to a path no context matched, so a request no route expects still fails. */
    private static final Reply NOT_FOUND = new Reply(404, "<h1>404 Not Found</h1>No context found for request",
            Map.of("Content-Type", List.of("text/html")));

    private final LoopbackPayer payer = new LoopbackPayer();

    enum Path {
        HOOK_ERROR_BODY, HOOK_RESPONSE_HEADERS, HOOK_UNPARSEABLE_2XX, HOOK_UNMAPPABLE_2XX,
        FIRST_TOKEN_FAILURE, REFRESH_AFTER_401_FAILS, REFRESH_AFTER_401_ECHOES, REQUEST_SERIALIZATION,
        TOKEN_IN_SERVICE_ID
    }

    @BeforeEach
    void routesOnly() {
        payer.otherwise(request -> NOT_FOUND);
    }

    @AfterEach
    void stop() {
        payer.close();
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void tokenAppearsNowhere(Path path) throws Exception {
        AtomicInteger tokens = new AtomicInteger();
        AtomicInteger hooks = new AtomicInteger();
        boolean oauth = switch (path) {
            case FIRST_TOKEN_FAILURE, REFRESH_AFTER_401_FAILS, REFRESH_AFTER_401_ECHOES -> true;
            default -> false;
        };
        payer.on("/token", request -> {
            int n = tokens.incrementAndGet();
            boolean fail = path == Path.FIRST_TOKEN_FAILURE || path == Path.REFRESH_AFTER_401_FAILS && n == 2;
            boolean echo = path != Path.REFRESH_AFTER_401_FAILS || n == 2;
            Reply reply;
            if (fail) {
                reply = plain(400, "{\"error\":\"invalid_client\",\"error_description\":\"saw " + TOKEN + "\"}");
            } else {
                String scope = n > 1 ? TOKEN : "crd";
                reply = plain(200, "{\"access_token\":\"payer-" + n + "\",\"token_type\":\"Bearer\","
                        + "\"expires_in\":300,\"scope\":\"" + scope + "\"}");
            }
            if (echo && n > 1 || path == Path.FIRST_TOKEN_FAILURE) {
                reply = reply.withHeader("X-Request-Id", TOKEN)
                        .withHeader("WWW-Authenticate", "Bearer error=\"" + TOKEN + "\"");
            }
            return reply;
        });
        payer.on("/cds-services/x", request -> {
            int n = hooks.incrementAndGet();
            return switch (path) {
                case HOOK_ERROR_BODY -> respond(400, "{\"error\":\"bad " + TOKEN + "\"}", false);
                case HOOK_RESPONSE_HEADERS -> respond(200, OK, true);
                case HOOK_UNPARSEABLE_2XX -> respond(200, "{\"cards\":" + TOKEN + "}", false);
                case HOOK_UNMAPPABLE_2XX -> respond(200, "{\"cards\":[{\"suggestions\":[\"" + TOKEN + "\"]}]}", false);
                case REFRESH_AFTER_401_FAILS, REFRESH_AFTER_401_ECHOES -> respond(n == 1 ? 401 : 200, OK, false);
                default -> respond(200, OK, false);
            };
        });
        payer.on("/cds-services/" + TOKEN, respond(400, "{\"error\":\"no\"}", false));
        Map<String, Object> context = path == Path.REQUEST_SERIALIZATION
                ? Map.of("patientId", "pat-1", TOKEN, new Object()) : Map.of("patientId", "pat-1");
        CdsHookRequest request = new CdsHookRequest("order-sign", "instance", context, Map.of())
                .withFhirServer(EHR, new FhirAuthorization(TOKEN, "Bearer", 300, "patient/Patient.read", "payer-client"));
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), secrets(), null,
                Duration.ofSeconds(5), Duration.ofSeconds(1), exchanges::add);

        RuntimeException thrown = null;
        try {
            client.callHook(record(oauth), path == Path.TOKEN_IN_SERVICE_ID ? TOKEN : "x", request);
        } catch (RuntimeException e) {
            thrown = e;
        }

        boolean succeeds = path == Path.HOOK_RESPONSE_HEADERS || path == Path.REFRESH_AFTER_401_ECHOES;
        assertEquals(succeeds, thrown == null, () -> path + " outcome");
        // Nothing is sent for a request that cannot be serialised; an exchange whose own URI names the token
        // is not delivered.
        boolean silent = path == Path.REQUEST_SERIALIZATION || path == Path.TOKEN_IN_SERVICE_ID;
        assertEquals(silent, exchanges.isEmpty(), "exchanges are reported unless nothing is sent");
        assertNoToken(exchanges, thrown);
        if (path == Path.REFRESH_AFTER_401_FAILS || path == Path.REFRESH_AFTER_401_ECHOES) {
            assertEquals(List.of(PayerCallPhase.TOKEN, PayerCallPhase.HOOK, PayerCallPhase.TOKEN),
                    exchanges.stream().map(PayerExchange::phase).limit(3).toList());
        }
        if (thrown instanceof PayerCallException e && path == Path.REFRESH_AFTER_401_FAILS) {
            assertEquals(PayerCallPhase.TOKEN, e.phase());
            assertEquals(400, e.statusCode().orElseThrow());
            assertTrue(e.responseBody().contains("invalid_client"), e.responseBody());
        }
    }

    /** The one check: no captured exchange and no thrown exception shows the token anywhere. */
    static void assertNoToken(List<PayerExchange> exchanges, Throwable thrown) {
        for (PayerExchange exchange : exchanges) {
            assertAbsent(exchange.toString(), "exchange");
            assertUriAbsent(exchange.uri());
            assertAbsent(String.valueOf(exchange.requestBody()), "requestBody");
            assertAbsent(String.valueOf(exchange.responseBody()), "responseBody");
            assertHeadersAbsent(exchange.requestHeaders());
            assertHeadersAbsent(exchange.responseHeaders());
            assertAbsent(PayerExchangeMetadata.from(exchange).toString(), "metadata");
            if (exchange.error() != null) {
                assertChainAbsent(exchange.error());
            }
        }
        if (thrown != null) {
            assertChainAbsent(thrown);
            if (thrown instanceof PayerCallException e) {
                assertAbsent(String.valueOf(e.responseBody()), "PayerCallException.responseBody");
                assertUriAbsent(e.uri());
                assertAbsent(String.valueOf(e.payerId()), "PayerCallException.payerId");
                assertHeadersAbsent(e.responseHeaders());
            }
        }
    }

    private static void assertChainAbsent(Throwable error) {
        StringWriter printed = new StringWriter();
        error.printStackTrace(new PrintWriter(printed));
        assertAbsent(printed.toString(), "printed stack trace");
        Set<Throwable> seen = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        List<Throwable> todo = new ArrayList<>(List.of(error));
        while (!todo.isEmpty()) {
            Throwable t = todo.remove(todo.size() - 1);
            if (seen.add(t)) {
                assertAbsent(String.valueOf(t), "chain");
                assertAbsent(String.valueOf(t.getMessage()), "message");
                assertAbsent(String.valueOf(t.getLocalizedMessage()), "localized message");
                if (t.getCause() != null) {
                    todo.add(t.getCause());
                }
                todo.addAll(List.of(t.getSuppressed()));
            }
        }
    }

    private static void assertUriAbsent(java.net.URI uri) {
        if (uri != null) {
            assertAbsent(uri.toString(), "uri");
            assertAbsent(String.valueOf(uri.getAuthority()) + uri.getPath() + uri.getQuery() + uri.getFragment(), "decoded uri");
        }
    }

    private static void assertHeadersAbsent(HttpHeaders headers) {
        headers.map().forEach((name, values) -> {
            assertAbsent(name, "header name");
            values.forEach(value -> assertAbsent(value, "header " + name));
        });
    }

    private static void assertAbsent(String text, String where) {
        assertFalse(text.contains(TOKEN), () -> where + ": " + text);
    }

    private static Reply respond(int status, String body, boolean echoHeaders) {
        Reply reply = plain(status, body);
        return echoHeaders ? reply.withHeader("X-Request-Id", TOKEN) : reply;
    }

    /** {@code body} with no Content-Type, as the hand-rolled server sent it. */
    private static Reply plain(int status, String body) {
        return new Reply(status, body, Map.of());
    }

    private ConnectionRecord record(boolean oauth) {
        return (oauth ? TestRecords.oauth2(payer) : TestRecords.none(payer)).payerId("payer").build();
    }

    private static CredentialProvider secrets() {
        return new CredentialProvider() {
            public Optional<String> resolve(String ref) { return Optional.of("client-secret"); }
            public void put(String ref, String value) { throw new UnsupportedOperationException(); }
            public void remove(String ref) { throw new UnsupportedOperationException(); }
        };
    }
}
