package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.Card;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.SystemAction;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Checks what {@code CdsHooksClient.callHook} decoded against the response body as it came off the
 * wire, read here with a plain {@link ObjectMapper}: every card and system action, their
 * representative fields, and every coverage-information extension the CRD response carries
 * (<a href="https://hl7.org/fhir/us/davinci-crd/STU2.2/cards.html#coverage-information">CRD 2.2.1
 * Coverage Information</a>, in {@code systemActions} or in card suggestion actions).
 */
final class ParsedResponseCheck {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ParsedResponseCheck() {
    }

    /** Fails unless {@code parsed} holds exactly what {@code wireBody} says; returns a one-line summary. */
    static String assertMatchesWire(String wireBody, CdsHookResponse parsed) {
        JsonNode wire;
        try {
            wire = MAPPER.readTree(wireBody);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        assertEquals(wire, parsed.rawJson(), "rawJson");

        JsonNode cards = wire.path("cards");
        assertEquals(cards.size(), parsed.cards().size(), "cards decoded");
        for (int i = 0; i < cards.size(); i++) {
            JsonNode expected = cards.get(i);
            Card card = parsed.cards().get(i);
            String where = "cards[" + i + "].";
            assertEquals(text(expected, "uuid"), card.uuid(), where + "uuid");
            assertEquals(text(expected, "summary"), card.summary(), where + "summary");
            assertEquals(text(expected, "detail"), card.detail(), where + "detail");
            assertEquals(text(expected, "indicator"), card.indicator(), where + "indicator");
            assertEquals(text(expected, "selectionBehavior"), card.selectionBehavior(), where + "selectionBehavior");
            assertEquals(text(expected.path("source"), "label"), card.source() == null ? null : card.source().label(),
                    where + "source.label");
            assertEquals(expected.path("suggestions").size(), size(card.suggestions()), where + "suggestions");
            assertEquals(expected.path("links").size(), size(card.links()), where + "links");
        }

        JsonNode actions = wire.path("systemActions");
        assertEquals(actions.size(), parsed.systemActions().size(), "systemActions decoded");
        for (int i = 0; i < actions.size(); i++) {
            JsonNode expected = actions.get(i);
            SystemAction action = parsed.systemActions().get(i);
            String where = "systemActions[" + i + "].";
            assertEquals(text(expected, "type"), action.type(), where + "type");
            assertEquals(text(expected, "description"), action.description(), where + "description");
            assertEquals(text(expected, "resourceId"), action.resourceId(), where + "resourceId");
            assertEquals(expected.get("resource"), action.resource(), where + "resource");
        }

        List<JsonNode> extensions = coverageInformationExtensions(wire);
        List<CoverageInformation> extracted = parsed.coverageInformation();
        assertEquals(extensions.size(), extracted.size(), "coverage-information extracted");
        for (int i = 0; i < extensions.size(); i++) {
            JsonNode ext = extensions.get(i);
            CoverageInformation info = extracted.get(i);
            String where = "coverageInformation[" + i + "].";
            assertEquals(sub(ext, "coverage", "valueReference"), info.coverage(), where + "coverage");
            assertEquals(sub(ext, "covered", "valueCode"), info.covered(), where + "covered");
            assertEquals(sub(ext, "pa-needed", "valueCode"), info.paNeeded(), where + "paNeeded");
            assertEquals(sub(ext, "date", "valueDate"), info.date(), where + "date");
        }
        return "cards=" + cards.size() + " systemActions=" + actions.size()
                + " coverageInformation=" + extensions.size() + " (all match the wire)";
    }

    /** Coverage-information extensions in the order CRD clients see them: system actions, then cards. */
    private static List<JsonNode> coverageInformationExtensions(JsonNode wire) {
        List<JsonNode> resources = new ArrayList<>();
        wire.path("systemActions").forEach(action -> resources.add(action.path("resource")));
        for (JsonNode card : wire.path("cards")) {
            for (JsonNode suggestion : card.path("suggestions")) {
                suggestion.path("actions").forEach(action -> resources.add(action.path("resource")));
            }
        }
        List<JsonNode> extensions = new ArrayList<>();
        for (JsonNode resource : resources) {
            for (JsonNode ext : resource.path("extension")) {
                if (CoverageInformation.EXTENSION_URL.equals(ext.path("url").asText())) {
                    extensions.add(ext);
                }
            }
        }
        return extensions;
    }

    private static String sub(JsonNode ext, String url, String valueField) {
        for (JsonNode sub : ext.path("extension")) {
            if (url.equals(sub.path("url").asText())) {
                JsonNode value = sub.path(valueField);
                return text(value.isObject() ? value : sub, value.isObject() ? "reference" : valueField);
            }
        }
        return null;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static int size(List<?> list) {
        return list == null ? 0 : list.size();
    }
}
