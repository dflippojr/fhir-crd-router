package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.fhircrdrouter.client.Card;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.client.CdsServiceDescriptor;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.InputStream;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end check against a running HL7 Da Vinci CRD reference
 * implementation (https://github.com/HL7-DaVinci/CRD). Skipped unless
 * {@code CRD_RI_BASE_URL} is set, e.g.:
 *
 * <pre>
 * docker build -t crd-ri https://github.com/HL7-DaVinci/CRD.git#master
 * docker run -d -p 18090:8090 crd-ri
 * CRD_RI_BASE_URL=http://127.0.0.1:18090/r4 ./mvnw -pl client-sdk -am test
 * </pre>
 *
 * <p>The host port is 18090 rather than the server's default 8090 because
 * 8090 is a common port for other local services (e.g. llama.cpp), and
 * {@code localhost} may resolve to a different listener over IPv4 vs IPv6.
 */
@EnabledIfEnvironmentVariable(named = "CRD_RI_BASE_URL", matches = ".+")
class CrdReferenceServerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final CdsHooksClient client = new CdsHooksClient(new NoCredentials());
    private final ConnectionRecord record = ConnectionRecord.builder()
            .payerId("HL7-CRD-RI")
            .displayName("HL7 Da Vinci CRD reference implementation")
            .environment(Environment.SANDBOX)
            .baseUrl(System.getenv("CRD_RI_BASE_URL"))
            .authType(AuthType.NONE)
            .build();

    @Test
    void discoversCrdServicesWithPrefetchTemplates() {
        List<CdsServiceDescriptor> services = client.discoverServices(record);

        CdsServiceDescriptor orderSign = services.stream()
                .filter(s -> "order-sign".equals(s.hook()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no order-sign service in " + services));
        assertFalse(orderSign.prefetch().isEmpty(), "reference server advertises prefetch templates");
    }

    @Test
    void orderSignReturnsCardsAndCoverageInformation() throws Exception {
        JsonNode fixture;
        try (InputStream in = getClass().getResourceAsStream("/crd-ri/order-sign-hospital-bed.json")) {
            fixture = mapper.readTree(in);
        }
        JsonNode r = fixture.get("resources");
        JsonNode deviceRequest = r.get("deviceRequest");

        String serviceId = client.discoverServices(record).stream()
                .filter(s -> "order-sign".equals(s.hook()))
                .map(CdsServiceDescriptor::id)
                .findFirst()
                .orElseThrow();

        // The reference server wants its own prefetch keys (from discovery), not CRD's "patient"/"coverage".
        CdsHookRequest request = CdsHookRequest.of(
                new CrdHookContext.OrderSign(fixture.get("userId").asText(), fixture.get("patientId").asText(), null,
                        bundle("collection", deviceRequest)),
                CrdPrefetch.builder()
                        .put("deviceRequestBundle", bundle("searchset", deviceRequest, r.get("patient"),
                                r.get("practitioner"), r.get("payer"), r.get("location"), r.get("practitionerRole"),
                                r.get("coverage")))
                        .put("coverageBundle", bundle("searchset", r.get("coverage")))
                        .build());

        CdsHookResponse response = client.callHook(record, serviceId, request);

        assertFalse(response.cards().isEmpty(), "expected at least one card, got " + response.rawJson());
        Card card = response.cards().get(0);
        // The rule's decision depends on the reference server's CQL; assert only that the right rule matched.
        assertTrue(card.summary().startsWith("Hospital Beds And Accessories"), card.summary());
        assertFalse(card.source().label().isBlank(), "CRD requires source.label");
        assertEquals("http://hl7.org/fhir/us/davinci-crd/CodeSystem/cardType", card.source().topic().system());

        List<CoverageInformation> coverage = response.coverageInformation();
        assertFalse(coverage.isEmpty(), "expected coverage-information, got " + response.rawJson());
        assertEquals("DeviceRequest/devreq-1", coverage.get(0).resourceReference());
        assertEquals("Coverage/cov-1", coverage.get(0).coverage());
        assertNotNull(coverage.get(0).coverageAssertionId(), "reference server sends its assertion id as \"identifier\"");
    }

    private JsonNode bundle(String type, JsonNode... resources) {
        ObjectNode bundle = mapper.createObjectNode().put("resourceType", "Bundle").put("type", type);
        ArrayNode entries = bundle.putArray("entry");
        for (JsonNode resource : resources) {
            entries.addObject().set("resource", resource);
        }
        return bundle;
    }

    private static final class NoCredentials implements CredentialProvider {
        @Override public Optional<String> resolve(String credentialRef) { return Optional.empty(); }
        @Override public void put(String credentialRef, String secretValue) { }
        @Override public void remove(String credentialRef) { }
    }
}
