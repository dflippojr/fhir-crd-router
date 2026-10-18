package io.github.dflippojr.fhircrdrouter.client.crd;

import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@link ParsedResponseCheck}, which {@code InfernoCrdClientSuiteTest} runs on every hook response,
 * against a populated synthetic response through the real client, so it runs without Inferno.
 */
class ParsedResponseCheckTest {

    private static final CredentialProvider NO_CREDENTIALS = new CredentialProvider() {
        @Override public Optional<String> resolve(String credentialRef) { return Optional.empty(); }
        @Override public void put(String credentialRef, String secretValue) { }
        @Override public void remove(String credentialRef) { }
    };
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance",
            Map.of("patientId", "p"), null);

    @Test
    void theClientDecodesEveryCardSystemActionAndCoverageDetermination() throws IOException {
        String body = fixture();
        AtomicReference<String> wire = new AtomicReference<>();
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.reset(r -> new LoopbackPayer.Reply(200, body));
            CdsHooksClient client = new CdsHooksClient(NO_CREDENTIALS, CdsHooksClient.DEFAULT_REQUEST_TIMEOUT,
                    CdsHooksClient.DEFAULT_CONNECT_TIMEOUT, exchange -> {
                        if (exchange.phase() == PayerCallPhase.HOOK) {
                            wire.set(exchange.responseBody());
                        }
                    });
            CdsHookResponse response = client.callHook(record(payer.origin()), "order-sign-crd", REQUEST);

            assertEquals(body, wire.get());
            assertEquals("cards=2 systemActions=2 coverageInformation=2 (all match the wire)",
                    ParsedResponseCheck.assertMatchesWire(wire.get(), response));
        }
    }

    @Test
    void aDroppedCardOrSystemActionFailsTheCheck() throws IOException {
        String body = fixture();
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.reset(r -> new LoopbackPayer.Reply(200, body));
            CdsHooksClient client = new CdsHooksClient(NO_CREDENTIALS);
            CdsHookResponse full = client.callHook(record(payer.origin()), "order-sign-crd", REQUEST);

            CdsHookResponse noCards = new CdsHookResponse(List.of(), full.systemActions(), full.rawJson());
            CdsHookResponse noActions = new CdsHookResponse(full.cards(), List.of(), full.rawJson());
            assertThrows(AssertionFailedError.class, () -> ParsedResponseCheck.assertMatchesWire(body, noCards));
            assertThrows(AssertionFailedError.class, () -> ParsedResponseCheck.assertMatchesWire(body, noActions));
        }
    }

    private static ConnectionRecord record(String origin) {
        return ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl(origin).authType(AuthType.NONE).build();
    }

    private String fixture() throws IOException {
        try (InputStream in = getClass().getResourceAsStream("/inferno/populated-response.json")) {
            assertNotNull(in, "missing fixture /inferno/populated-response.json");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
