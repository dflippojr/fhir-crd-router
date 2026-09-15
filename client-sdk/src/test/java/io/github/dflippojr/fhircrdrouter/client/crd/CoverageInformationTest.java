package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CoverageInformationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void parsesCrd2SystemActionShape() throws Exception {
        JsonNode raw = mapper.readTree("""
                {"cards":[],"systemActions":[{"type":"update","resource":{
                  "resourceType":"ServiceRequest","id":"sr1",
                  "extension":[
                    {"url":"http://example.org/unrelated","valueString":"ignored"},
                    {"url":"http://hl7.org/fhir/us/davinci-crd/StructureDefinition/ext-coverage-information","extension":[
                      {"url":"coverage","valueReference":{"reference":"Coverage/cov1"}},
                      {"url":"covered","valueCode":"covered"},
                      {"url":"pa-needed","valueCode":"auth-needed"},
                      {"url":"doc-needed","valueCode":"clinical"},
                      {"url":"info-needed","valueCode":"performer"},
                      {"url":"info-needed","valueCode":"location"},
                      {"url":"date","valueDate":"2026-09-15"},
                      {"url":"coverage-assertion-id","valueString":"assert-1"}
                    ]}
                  ]}}]}""");

        List<CoverageInformation> infos = new CdsHookResponse(List.of(), List.of(), raw).coverageInformation();

        assertEquals(1, infos.size());
        CoverageInformation info = infos.get(0);
        assertEquals("ServiceRequest/sr1", info.resourceReference());
        assertEquals("Coverage/cov1", info.coverage());
        assertEquals("covered", info.covered());
        assertEquals("auth-needed", info.paNeeded());
        assertEquals(List.of("clinical"), info.docNeeded());
        assertEquals(List.of("performer", "location"), info.infoNeeded());
        assertEquals("2026-09-15", info.date());
        assertEquals("assert-1", info.coverageAssertionId());
        assertNull(info.satisfiedPaId());
    }

    /** Shape observed from the HL7 CRD reference implementation (2026-09): inside card suggestions, older names. */
    @Test
    void parsesReferenceImplementationSuggestionShape() throws Exception {
        JsonNode raw = mapper.readTree("""
                {"cards":[{"summary":"Documentation Required.","suggestions":[{"label":"Save Update To EHR","actions":[
                  {"type":"update","resource":{"resourceType":"DeviceRequest","id":"123","extension":[
                    {"url":"http://hl7.org/fhir/us/davinci-crd/StructureDefinition/ext-coverage-information","extension":[
                      {"url":"coverageInfo","valueCoding":{"code":"clinical"}},
                      {"url":"coverage","valueReference":{"reference":"Coverage/c1"}},
                      {"url":"identifier","valueString":"id-1"},
                      {"url":"doc-needed","valueCode":"admin"},
                      {"url":"questionnaire","valueCanonical":"http://localhost:8090/fhir/r4/Questionnaire/Beds"}
                    ]}
                  ]}}
                ]}]}]}""");

        List<CoverageInformation> infos = new CdsHookResponse(List.of(), List.of(), raw).coverageInformation();

        assertEquals(1, infos.size());
        CoverageInformation info = infos.get(0);
        assertEquals("DeviceRequest/123", info.resourceReference());
        assertEquals("id-1", info.coverageAssertionId());
        assertEquals(List.of("admin"), info.docNeeded());
        assertEquals(List.of("http://localhost:8090/fhir/r4/Questionnaire/Beds"), info.questionnaires());
        assertTrue(info.extension().has("extension"), "raw extension kept for unmodeled parts");
    }

    @Test
    void emptyWhenNoCoverageInformation() throws Exception {
        JsonNode raw = mapper.readTree("{\"cards\":[{\"summary\":\"hi\"}]}");
        assertTrue(new CdsHookResponse(List.of(), List.of(), raw).coverageInformation().isEmpty());
    }
}
