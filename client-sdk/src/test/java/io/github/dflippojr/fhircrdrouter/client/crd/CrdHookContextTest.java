package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrdHookContextTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void orderSignRequestSerializesToCdsHooksShape() throws Exception {
        JsonNode draftOrders = mapper.readTree("""
                {"resourceType":"Bundle","type":"collection","entry":[{"resource":{"resourceType":"ServiceRequest","id":"sr1"}}]}""");
        JsonNode patient = mapper.readTree("""
                {"resourceType":"Patient","id":"p1"}""");

        CdsHookRequest request = CdsHookRequest.of(
                new CrdHookContext.OrderSign("Practitioner/doc1", "p1", null, draftOrders),
                CrdPrefetch.builder().patient(patient).build());
        JsonNode json = mapper.valueToTree(request);

        assertEquals("order-sign", json.get("hook").asText());
        assertFalse(json.get("hookInstance").asText().isBlank());
        assertFalse(json.has("fhirServer"), "null fhirServer should be omitted");
        assertFalse(json.has("fhirAuthorization"));

        JsonNode context = json.get("context");
        assertEquals("Practitioner/doc1", context.get("userId").asText());
        assertEquals("p1", context.get("patientId").asText());
        assertFalse(context.has("encounterId"), "null encounterId should be omitted");
        assertFalse(context.has("hook"), "hook name belongs on the request, not in context");
        assertEquals("sr1", context.at("/draftOrders/entry/0/resource/id").asText());

        assertEquals("Patient", json.at("/prefetch/patient/resourceType").asText());
    }

    @Test
    void fhirAuthorizationUsesSnakeCaseAndDefaultsBearer() {
        CdsHookRequest request = CdsHookRequest.of(
                        new CrdHookContext.EncounterStart("Practitioner/doc1", "p1", "e1"), null)
                .withFhirServer("https://ehr.example/fhir",
                        new CdsHookRequest.FhirAuthorization("abc", null, 300, "patient/*.read", "payer-client"));
        JsonNode json = mapper.valueToTree(request);

        assertEquals("https://ehr.example/fhir", json.get("fhirServer").asText());
        assertEquals("abc", json.at("/fhirAuthorization/access_token").asText());
        assertEquals("Bearer", json.at("/fhirAuthorization/token_type").asText());
        assertEquals(300, json.at("/fhirAuthorization/expires_in").asInt());
        assertFalse(json.has("prefetch"));
    }

    @Test
    void validatesRequiredElementsAndShapes() throws Exception {
        JsonNode bundle = mapper.readTree("{\"resourceType\":\"Bundle\"}");
        JsonNode notBundle = mapper.readTree("{\"resourceType\":\"ServiceRequest\"}");

        assertThrows(IllegalArgumentException.class,
                () -> new CrdHookContext.OrderSign("doc1", "p1", null, bundle), "userId must be Type/id");
        assertThrows(IllegalArgumentException.class,
                () -> new CrdHookContext.OrderSign("Practitioner/doc1", " ", null, bundle));
        assertThrows(IllegalArgumentException.class,
                () -> new CrdHookContext.OrderSign("Practitioner/doc1", "p1", null, notBundle));
        assertThrows(IllegalArgumentException.class,
                () -> new CrdHookContext.OrderSelect("Practitioner/doc1", "p1", null, List.of("sr1"), bundle));
        assertThrows(IllegalArgumentException.class,
                () -> new CrdHookContext.OrderDispatch("p1", List.of(), null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new CrdHookContext.EncounterDischarge("Practitioner/doc1", "p1", null));
    }

    @Test
    void orderDispatchOmitsEmptyTasks() {
        JsonNode json = mapper.valueToTree(new CrdHookContext.OrderDispatch(
                "p1", List.of("ServiceRequest/sr1"), "Organization/lab1", List.of()));

        assertTrue(json.get("dispatchedOrders").isArray());
        assertEquals("Organization/lab1", json.get("performer").asText());
        assertFalse(json.has("fulfillmentTasks"));
    }
}
