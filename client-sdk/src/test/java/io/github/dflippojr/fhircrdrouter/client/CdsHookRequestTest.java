package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest.FhirAuthorization;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdHookContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code fhirServer} / {@code fhirAuthorization} rules of CDS Hooks 2.0:
 * https://cds-hooks.hl7.org/2.0/#http-request_1 and
 * https://cds-hooks.hl7.org/2.0/#passing-the-access-token-to-the-cds-service.
 */
class CdsHookRequestTest {

    private static final String EHR = "https://ehr.example/fhir";

    // Same configuration as CdsHooksClient's mapper.
    private final ObjectMapper mapper = new ObjectMapper();

    private static CdsHookRequest request() {
        return CdsHookRequest.of(new CrdHookContext.EncounterStart("Practitioner/doc1", "p1", "e1"), null);
    }

    private static FhirAuthorization auth() {
        return new FhirAuthorization("tok", "Bearer", 300, "patient/Patient.read", "payer-client");
    }

    private static void assertRejects(String field, Executable construct) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, construct);
        assertTrue(e.getMessage().contains(field), "message names " + field + ": " + e.getMessage());
    }

    @Test
    void rejectsMissingOrBlankRequiredFields() {
        assertRejects("accessToken", () -> new FhirAuthorization(null, "Bearer", 300, "s", "sub"));
        assertRejects("accessToken", () -> new FhirAuthorization(" ", "Bearer", 300, "s", "sub"));
        assertRejects("expiresIn", () -> new FhirAuthorization("tok", "Bearer", null, "s", "sub"));
        assertRejects("scope", () -> new FhirAuthorization("tok", "Bearer", 300, null, "sub"));
        assertRejects("scope", () -> new FhirAuthorization("tok", "Bearer", 300, "", "sub"));
        assertRejects("subject", () -> new FhirAuthorization("tok", "Bearer", 300, "s", null));
        assertRejects("subject", () -> new FhirAuthorization("tok", "Bearer", 300, "s", "\t"));
    }

    @Test
    void tokenTypeIsBearerOnly() {
        assertRejects("tokenType", () -> new FhirAuthorization("tok", "MAC", 300, "s", "sub"));
        assertRejects("tokenType", () -> new FhirAuthorization("tok", "", 300, "s", "sub"));
        assertEquals("Bearer", new FhirAuthorization("tok", null, 300, "s", "sub").tokenType());
        assertEquals("Bearer", new FhirAuthorization("tok", "Bearer", 300, "s", "sub").tokenType());
    }

    @Test
    void fhirAuthorizationRequiresFhirServer() {
        CdsHookRequest request = request();
        assertRejects("fhirServer", () -> request.withFhirServer(null, auth()));
        assertRejects("fhirServer", () -> request.withFhirServer(" ", auth()));
        assertRejects("fhirServer", () -> new CdsHookRequest(
                "order-sign", "id", null, auth(), request.context(), null));
    }

    @Test
    void fhirServerWithoutAuthorizationIsAllowed() {
        JsonNode json = mapper.valueToTree(request().withFhirServer(EHR, null));
        assertEquals(EHR, json.path("fhirServer").asText());
        assertFalse(json.has("fhirAuthorization"));
    }

    @Test
    void serializesEveryRequiredField() {
        JsonNode json = mapper.valueToTree(request().withFhirServer(EHR, auth()));

        assertEquals(EHR, json.path("fhirServer").asText());
        JsonNode auth = json.path("fhirAuthorization");
        assertEquals("tok", auth.path("access_token").asText());
        assertEquals("Bearer", auth.path("token_type").asText());
        assertEquals(300, auth.path("expires_in").asInt());
        assertEquals("patient/Patient.read", auth.path("scope").asText());
        assertEquals("payer-client", auth.path("subject").asText());
        assertFalse(auth.has("patient"), "a null patient is omitted: " + auth);
    }

    @Test
    void patientRoundTripsThroughTheMapper() throws Exception {
        String wire = """
                {"access_token":"tok","token_type":"Bearer","expires_in":300,\
                "scope":"patient/Patient.read","subject":"payer-client","patient":"p1"}""";

        FhirAuthorization read = mapper.readValue(wire, FhirAuthorization.class);
        JsonNode written = mapper.valueToTree(request().withFhirServer(EHR, read));

        assertEquals(mapper.readTree(wire), written.path("fhirAuthorization"));
        assertEquals("p1", written.at("/fhirAuthorization/patient").asText());
        assertEquals(read, new FhirAuthorization("tok", null, 300, "patient/Patient.read", "payer-client", "p1"));
    }
}
