package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CdsDiscoveryValidatorTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void acceptsCompleteCustomAndEmptyCatalogs() throws Exception {
        for (String json : List.of("{\"services\":[]}", """
                {"extra":true,"services":[
                  {"id":"same","hook":"payer-custom","description":"desc","title":"",
                   "prefetch":{"payerKey":"Anything?value={{context.custom}}"},"extra":42},
                  {"id":"same","hook":"other-hook","description":"desc","prefetch":{}},
                  {"id":"minimal","hook":"order-sign","description":"desc"}]}
                """)) {
            assertEquals(List.of(), CdsDiscoveryValidator.validate(mapper.readTree(json)));
        }
    }

    @Test
    void malformedParentsHaveOnlyOneFinding() throws Exception {
        assertPaths(null, "$");
        for (String json : List.of("null", "[]", "1", "true", "\"text\"")) {
            assertPaths(mapper.readTree(json), "$");
        }
        for (String json : List.of("{}", "{\"services\":null}", "{\"services\":{}}",
                "{\"services\":1}", "{\"services\":\"text\"}")) {
            assertPaths(mapper.readTree(json), "services");
        }
        assertPaths(mapper.readTree("{\"services\":[null,[],42,true,\"text\"]}"),
                "services[0]", "services[1]", "services[2]", "services[3]", "services[4]");
    }

    @Test
    void requiredFieldsRejectMissingNullBlankAndNontextualValues() throws Exception {
        assertPaths(mapper.readTree("{\"services\":[{}]}"),
                "services[0].id", "services[0].hook", "services[0].description");
        for (String field : List.of("id", "hook", "description")) {
            for (String value : List.of("null", "\"\"", "\"  \\t\\n\"", "12", "true", "[]", "{}")) {
                JsonNode catalog = mapper.readTree("""
                        {"services":[{"id":"id","hook":"hook","description":"desc"}]}
                        """);
                ((com.fasterxml.jackson.databind.node.ObjectNode) catalog.get("services").get(0))
                        .set(field, mapper.readTree(value));
                assertPaths(catalog, "services[0]." + field);
            }
        }
    }

    @Test
    void optionalFieldsRejectWrongShapesAndPrefetchValues() throws Exception {
        for (String value : List.of("null", "12", "true", "[]", "{}")) {
            assertPaths(withOptional("title", value), "services[0].title");
        }
        for (String value : List.of("null", "12", "true", "[]", "\"text\"")) {
            assertPaths(withOptional("prefetch", value), "services[0].prefetch");
        }
        for (String value : List.of("null", "\"\"", "\" \\t\"", "12", "true", "[]", "{}")) {
            assertPaths(withOptional("prefetch", "{\"coverage\":" + value + "}"),
                    "services[0].prefetch.coverage");
        }
    }

    @Test
    void findingsAreImmutableOrderedAndDoNotEchoValues() throws Exception {
        JsonNode catalog = mapper.readTree("""
                {"services":[{"prefetch":{"z":null,"a":12},"title":false,
                 "description":false,"hook":{},"id":42},{}]}
                """);
        var findings = CdsDiscoveryValidator.validate(catalog);
        assertPaths(catalog, "services[0].id", "services[0].hook", "services[0].description",
                "services[0].title", "services[0].prefetch.z", "services[0].prefetch.a",
                "services[1].id", "services[1].hook", "services[1].description");
        assertEquals(findings, CdsDiscoveryValidator.validate(catalog));
        assertThrows(UnsupportedOperationException.class, () -> findings.clear());
        assertThrows(UnsupportedOperationException.class,
                () -> CdsDiscoveryValidator.validate(mapper.createObjectNode()).clear());
        assertEquals("id is required and must be a nonblank string", findings.get(0).message());
    }

    private JsonNode withOptional(String field, String value) throws Exception {
        return mapper.readTree("{\"services\":[{\"id\":\"id\",\"hook\":\"hook\",\"description\":\"desc\",\""
                + field + "\":" + value + "}]}");
    }

    private void assertPaths(JsonNode catalog, String... paths) {
        var findings = CdsDiscoveryValidator.validate(catalog);
        assertEquals(List.of(paths), findings.stream().map(CdsDiscoveryValidator.Violation::path).toList());
        findings.forEach(v -> {
            assertEquals(CdsDiscoveryValidator.Severity.ERROR, v.severity());
            assertFalse(v.message().isBlank());
        });
    }
}
