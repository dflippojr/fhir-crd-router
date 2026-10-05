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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

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

    private static final Set<String> CRD_HOOKS = Set.of("order-sign", "order-select", "order-dispatch",
            "appointment-book", "encounter-start", "encounter-discharge");

    @Test
    void everyDiscoveredServiceSatisfiesTheDiscoveryContract() throws Exception {
        String discoveryUrl = record.baseUrl() + (record.baseUrl().endsWith("/") ? "" : "/") + "cds-services";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(discoveryUrl))
                .timeout(Duration.ofSeconds(10)).GET().build();
        HttpResponse<String> response = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
                .send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        JsonNode services = mapper.readTree(response.body()).path("services");
        assertTrue(services.isArray() && !services.isEmpty(), "discovery must list services: " + response.body());
        List<CdsServiceDescriptor> parsed = client.discoverServices(record);
        assertEquals(services.size(), parsed.size(), "SDK must parse every advertised service");
        for (JsonNode service : services) {
            for (String field : List.of("id", "hook", "description")) {
                assertTrue(service.path(field).isTextual() && !service.path(field).asText().isBlank(),
                        "missing required " + field + " in " + service);
            }
            CdsServiceDescriptor descriptor = mapper.treeToValue(service, CdsServiceDescriptor.class);
            JsonNode prefetch = service.path("prefetch");
            assertTrue(prefetch.isMissingNode() || prefetch.isObject(), "prefetch must be an object: " + service);
            assertEquals(prefetch.size(), descriptor.prefetch().size(), "every template must parse: " + service);
            prefetch.fields().forEachRemaining(entry -> {
                assertTrue(entry.getValue().isTextual() && !entry.getValue().asText().isBlank(),
                        "invalid prefetch template " + entry.getKey() + " in " + service);
                assertEquals(entry.getValue().asText(), descriptor.prefetch().get(entry.getKey()));
            });
            System.out.println("RI discovery: service=" + descriptor.id() + " hook=" + descriptor.hook()
                    + (CRD_HOOKS.contains(descriptor.hook()) ? " (CRD)" : " (non-CRD hook; discovery only)"));
        }
    }

    @ParameterizedTest(name = "order-sign rule: {0}")
    @ValueSource(strings = {"hospital-bed", "home-oxygen"})
    void orderSignReturnsCardsAndCoverageInformation(String rule) throws Exception {
        JsonNode fixture = fixture(rule);
        JsonNode r = fixture.get("resources");
        JsonNode deviceRequest = r.get("deviceRequest");
        String serviceId = serviceFor("order-sign").id();

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
        String expectedRule = fixture.get("expectedRule").asText();
        assertTrue(response.cards().stream().anyMatch(c -> c.summary().startsWith(expectedRule)),
                "expected " + expectedRule + ", got " + response.rawJson());
        assertFalse(card.source().label().isBlank(), "CRD requires source.label");
        assertEquals("http://hl7.org/fhir/us/davinci-crd/CodeSystem/cardType", card.source().topic().system());

        List<CoverageInformation> coverage = response.coverageInformation();
        assertFalse(coverage.isEmpty(), "expected coverage-information, got " + response.rawJson());
        assertEquals("DeviceRequest/devreq-1", coverage.get(0).resourceReference());
        assertEquals("Coverage/cov-1", coverage.get(0).coverage());
        assertNotNull(coverage.get(0).coverageAssertionId(), "reference server sends its assertion id as \"identifier\"");
    }

    @ParameterizedTest(name = "typed CRD hook: {0}")
    @ValueSource(strings = {"order-select", "order-dispatch", "appointment-book", "encounter-start",
            "encounter-discharge"})
    void otherAdvertisedCrdHooksReturnParseableResponses(String hook) throws Exception {
        CdsServiceDescriptor service = serviceFor(hook);
        JsonNode fixture = fixture("hospital-bed");
        JsonNode r = fixture.get("resources");
        // These calls exercise the hook/response contract, not CQL rules. A synthetic
        // code also avoids the RI order-dispatch rule-card builder's null request bug.
        ObjectNode coding = (ObjectNode) r.path("deviceRequest").path("codeCodeableConcept")
                .path("coding").get(0);
        coding.put("system", "urn:example:crd-test").put("code", "synthetic-device");
        ((ObjectNode) r.path("deviceRequest").path("codeCodeableConcept"))
                .put("text", "Synthetic device for hook contract tests");
        ((ObjectNode) r.path("deviceRequest")).put("status", "active");
        String userId = fixture.get("userId").asText();
        String patientId = fixture.get("patientId").asText();
        JsonNode encounter = mapper.createObjectNode().put("resourceType", "Encounter")
                .put("id", "enc-1").put("status", "in-progress");
        ((ObjectNode) encounter).putObject("class").put("system", "http://terminology.hl7.org/CodeSystem/v3-ActCode")
                .put("code", "AMB");
        ((ObjectNode) encounter).putObject("subject").put("reference", "Patient/" + patientId);
        ObjectNode appointment = mapper.createObjectNode().put("resourceType", "Appointment")
                .put("id", "appt-1").put("status", "proposed");
        ObjectNode participant = appointment.putArray("participant").addObject().put("status", "needs-action");
        participant.putObject("actor").put("reference", "Patient/" + patientId);
        CrdHookContext context = switch (hook) {
            case "order-select" -> new CrdHookContext.OrderSelect(userId, patientId, "enc-1",
                    List.of("DeviceRequest/devreq-1"), bundle("collection", r.get("deviceRequest")));
            case "order-dispatch" -> new CrdHookContext.OrderDispatch(patientId,
                    List.of("DeviceRequest/devreq-1"), "PractitionerRole/role-1", null);
            case "appointment-book" -> new CrdHookContext.AppointmentBook(userId, patientId, "enc-1",
                    bundle("collection", appointment));
            case "encounter-start" -> new CrdHookContext.EncounterStart(userId, patientId, "enc-1");
            case "encounter-discharge" -> new CrdHookContext.EncounterDischarge(userId, patientId, "enc-1");
            default -> throw new IllegalArgumentException("unsupported CRD hook: " + hook);
        };
        CdsHookRequest request = CdsHookRequest.of(context, CrdPrefetch.builder()
                .put("deviceRequestBundle", bundle("searchset", r.get("deviceRequest"), r.get("patient"),
                        r.get("practitioner"), r.get("payer"), r.get("location"), r.get("practitionerRole"),
                        r.get("coverage")))
                .put("coverageBundle", bundle("searchset", r.get("coverage")))
                .put("encounterBundle", bundle("searchset", encounter, r.get("patient")))
                .put("appointmentBundle", bundle("searchset", appointment, r.get("patient")))
                .patient(r.get("patient")).encounter(encounter).build());
        CdsHookResponse response = client.callHook(record, service.id(), request);
        assertTrue(response.rawJson().isObject(), hook + " response: " + response.rawJson());
        assertTrue(response.rawJson().path("cards").isArray(), hook + " response: " + response.rawJson());
        assertNotNull(response.cards(), hook + " cards parse");
        assertNotNull(response.systemActions(), hook + " system actions parse");
        response.coverageInformation();
        System.out.println("RI typed hook: " + hook + " service=" + service.id() + " parsed successfully");
    }

    private CdsServiceDescriptor serviceFor(String hook) {
        Optional<CdsServiceDescriptor> service = client.discoverServices(record).stream()
                .filter(s -> hook.equals(s.hook())).findFirst();
        String message = "RI does not advertise " + hook + "; skipping hook call";
        if (service.isEmpty()) {
            System.out.println(message);
        }
        assumeTrue(service.isPresent(), message);
        return service.orElseThrow();
    }

    private JsonNode fixture(String rule) throws Exception {
        String path = "/crd-ri/order-sign-" + rule + ".json";
        try (InputStream in = getClass().getResourceAsStream(path)) {
            assertNotNull(in, "missing synthetic fixture " + path);
            return mapper.readTree(in);
        }
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
