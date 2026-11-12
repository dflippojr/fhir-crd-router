package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest.FhirAuthorization;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The EHR's FHIR {@code access_token} sent in a hook request's {@code fhirAuthorization}
 * (<a href="https://cds-hooks.hl7.org/2.0/#passing-the-access-token-to-the-cds-service">CDS Hooks 2.0,
 * Passing the Access Token to the CDS Service</a>) never reaches a listener: not in the request body,
 * not echoed in the response body, and not in {@link PayerExchange#toString()} (#164).
 */
class PayerExchangeFhirAuthorizationTest {
    private static final String TOKEN = "SENTINEL-EHR-ACCESS-TOKEN-164";
    private static final String EHR = "https://ehr.example.org/fhir";
    private static final FhirAuthorization AUTH =
            new FhirAuthorization(TOKEN, "Bearer", 300, "patient/Patient.read", "payer-client", "pat-1");
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance",
            Map.of("patientId", "pat-1"), Map.of()).withFhirServer(EHR, AUTH);
    private final ObjectMapper mapper = new ObjectMapper();
    private final List<PayerExchange> exchanges = new ArrayList<>();
    private final LoopbackPayer payer = new LoopbackPayer();

    @AfterEach
    void stop() {
        payer.close();
    }

    @Test
    void hookRequestBodyRedactsOnlyTheAccessToken() throws Exception {
        payer.reset(r -> new LoopbackPayer.Reply(200, "{\"cards\":[]}"));

        client().callHook(record(), "x", REQUEST);

        // The payer still gets the token: redaction is for listeners only.
        assertEquals(TOKEN, mapper.readTree(payer.received().get(0).body())
                .at("/fhirAuthorization/access_token").asText());
        PayerExchange hook = single();
        assertNoToken(hook);
        JsonNode sent = mapper.readTree(hook.requestBody());
        assertEquals("[REDACTED]", sent.at("/fhirAuthorization/access_token").asText());
        // Everything else in the body is what was sent, so a listener can still debug the call.
        JsonNode expected = mapper.valueToTree(REQUEST);
        ((com.fasterxml.jackson.databind.node.ObjectNode) expected.get("fhirAuthorization"))
                .put("access_token", "[REDACTED]");
        assertEquals(expected, sent);
    }

    @Test
    void tokenEchoedInHookResponseBodyIsRedacted() throws Exception {
        payer.reset(r -> new LoopbackPayer.Reply(200,
                "{\"cards\":[{\"summary\":\"saw " + TOKEN + "\",\"indicator\":\"info\",\"source\":{\"label\":\"p\"}}]}"));

        client().callHook(record(), "x", REQUEST);

        PayerExchange hook = single();
        assertNoToken(hook);
        assertTrue(hook.responseBody().contains("saw [REDACTED]"), hook.responseBody());
    }

    @Test
    void tokenEchoedInHookErrorBodyIsRedacted() {
        payer.reset(r -> new LoopbackPayer.Reply(400, "{\"error\":\"bad token " + TOKEN + "\"}"));

        assertThrows(PayerCallException.class, () -> client().callHook(record(), "x", REQUEST));

        PayerExchange hook = single();
        assertNoToken(hook);
        assertTrue(hook.responseBody().contains("bad token [REDACTED]"), hook.responseBody());
    }

    private PayerExchange single() {
        assertEquals(1, exchanges.size());
        PayerExchange hook = exchanges.get(0);
        assertEquals(PayerCallPhase.HOOK, hook.phase());
        return hook;
    }

    private static void assertNoToken(PayerExchange exchange) {
        assertFalse(exchange.toString().contains(TOKEN), exchange.toString());
        assertFalse(exchange.requestBody().contains(TOKEN), exchange.requestBody());
        assertFalse(exchange.responseBody().contains(TOKEN), exchange.responseBody());
        assertFalse(PayerExchangeMetadata.from(exchange).toString().contains(TOKEN));
    }

    private ConnectionRecord record() {
        return ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                .baseUrl(payer.origin()).authType(AuthType.NONE).build();
    }

    private CdsHooksClient client() {
        CredentialProvider credentials = new CredentialProvider() {
            public Optional<String> resolve(String ref) { return Optional.empty(); }
            public void put(String ref, String value) { throw new UnsupportedOperationException(); }
            public void remove(String ref) { throw new UnsupportedOperationException(); }
        };
        return new CdsHooksClient(HttpClient.newHttpClient(), credentials, null, Duration.ofSeconds(5),
                Duration.ofSeconds(1), exchanges::add);
    }
}
