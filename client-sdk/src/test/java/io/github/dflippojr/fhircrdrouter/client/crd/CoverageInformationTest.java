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

    /** When a payer sends both names, coverage-assertion-id wins over the legacy identifier, in either order. */
    @Test
    void coverageAssertionIdWinsOverLegacyIdentifier() throws Exception {
        String assertion = "{\"url\":\"coverage-assertion-id\",\"valueString\":\"assert-1\"}";
        String legacy = "{\"url\":\"identifier\",\"valueString\":\"id-1\"}";
        for (String subs : List.of(assertion + "," + legacy, legacy + "," + assertion)) {
            JsonNode resource = mapper.readTree("""
                    {"resourceType":"ServiceRequest","extension":[
                      {"url":"%s","extension":[%s]}
                    ]}""".formatted(CoverageInformation.EXTENSION_URL, subs));

            List<CoverageInformation> infos = CoverageInformation.fromResource(resource);

            assertEquals(1, infos.size());
            assertEquals("assert-1", infos.get(0).coverageAssertionId(), subs);
        }
    }

    /** CRD 2.2.1 ext-coverage-information: satisfied-pa-id names the prior auth already satisfied. */
    @Test
    void parsesSatisfiedPaId() throws Exception {
        JsonNode resource = mapper.readTree("""
                {"resourceType":"ServiceRequest","id":"sr1","extension":[
                  {"url":"%s","extension":[
                    {"url":"pa-needed","valueCode":"satisfied"},
                    {"url":"satisfied-pa-id","valueString":"pa-9"}
                  ]}
                ]}""".formatted(CoverageInformation.EXTENSION_URL));

        List<CoverageInformation> infos = CoverageInformation.fromResource(resource);

        assertEquals(1, infos.size());
        assertEquals("satisfied", infos.get(0).paNeeded());
        assertEquals("pa-9", infos.get(0).satisfiedPaId());
    }

    /** No id means no reference, not "ServiceRequest/null". */
    @Test
    void resourceWithoutIdHasNoReference() throws Exception {
        JsonNode resource = mapper.readTree("""
                {"resourceType":"ServiceRequest","extension":[
                  {"url":"%s","extension":[{"url":"covered","valueCode":"covered"}]}
                ]}""".formatted(CoverageInformation.EXTENSION_URL));

        List<CoverageInformation> infos = CoverageInformation.fromResource(resource);

        assertEquals(1, infos.size());
        assertNull(infos.get(0).resourceReference());
        assertEquals("covered", infos.get(0).covered());
    }

    /** A JSON null value reads as absent: no "null" string, nothing added to the lists. */
    @Test
    void nullValuesReadAsAbsent() throws Exception {
        JsonNode resource = mapper.readTree("""
                {"resourceType":"ServiceRequest","id":"sr1","extension":[
                  {"url":"%s","extension":[
                    {"url":"covered","valueCode":null},
                    {"url":"doc-needed","valueCode":null},
                    {"url":"info-needed","valueCode":null}
                  ]}
                ]}""".formatted(CoverageInformation.EXTENSION_URL));

        List<CoverageInformation> infos = CoverageInformation.fromResource(resource);

        assertEquals(1, infos.size());
        CoverageInformation info = infos.get(0);
        assertNull(info.covered());
        assertEquals(List.of(), info.docNeeded());
        assertEquals(List.of(), info.infoNeeded());
    }

    @Test
    void emptyWhenNoCoverageInformation() throws Exception {
        JsonNode raw = mapper.readTree("{\"cards\":[{\"summary\":\"hi\"}]}");
        assertTrue(new CdsHookResponse(List.of(), List.of(), raw).coverageInformation().isEmpty());
    }
}
