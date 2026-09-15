package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;

/**
 * One CRD {@code ext-coverage-information} extension, read off an order or
 * appointment the payer returned in a system action.
 *
 * <p>Code fields are kept as strings rather than enums so a payer on a newer
 * IG version with extra codes doesn't break parsing. Typical values:
 * {@code covered} = covered / not-covered / conditional;
 * {@code paNeeded} = no-auth / auth-needed / satisfied / performpa / conditional;
 * {@code docNeeded} and {@code infoNeeded} list what else is required.
 * Anything not modeled here is still available in {@link #extension()}.
 *
 * <p>Payers don't all emit the 2.x shape. The HL7 CRD reference
 * implementation, for example, sends {@code identifier} instead of
 * {@code coverage-assertion-id}; both are accepted.
 *
 * @param resourceReference {@code [ResourceType]/[id]} of the resource the extension was on, if it had an id
 * @param coverage the Coverage reference this determination applies to
 */
public record CoverageInformation(
        String resourceReference,
        String coverage,
        String covered,
        String paNeeded,
        List<String> docNeeded,
        List<String> infoNeeded,
        String date,
        String coverageAssertionId,
        String satisfiedPaId,
        List<String> questionnaires,
        JsonNode extension
) {
    public static final String EXTENSION_URL =
            "http://hl7.org/fhir/us/davinci-crd/StructureDefinition/ext-coverage-information";

    /** Parses every coverage-information extension on a FHIR resource (orders can carry one per Coverage). */
    public static List<CoverageInformation> fromResource(JsonNode resource) {
        List<CoverageInformation> result = new ArrayList<>();
        if (resource == null) {
            return result;
        }
        String reference = resource.hasNonNull("resourceType") && resource.hasNonNull("id")
                ? resource.get("resourceType").asText() + "/" + resource.get("id").asText()
                : null;
        for (JsonNode ext : resource.path("extension")) {
            if (EXTENSION_URL.equals(ext.path("url").asText())) {
                result.add(parse(reference, ext));
            }
        }
        return result;
    }

    private static CoverageInformation parse(String reference, JsonNode ext) {
        String coverage = null, covered = null, paNeeded = null, date = null, assertionId = null, satisfiedPaId = null;
        List<String> docNeeded = new ArrayList<>();
        List<String> infoNeeded = new ArrayList<>();
        List<String> questionnaires = new ArrayList<>();
        for (JsonNode sub : ext.path("extension")) {
            switch (sub.path("url").asText()) {
                case "coverage" -> coverage = textOrNull(sub.path("valueReference").path("reference"));
                case "covered" -> covered = textOrNull(sub.path("valueCode"));
                case "pa-needed" -> paNeeded = textOrNull(sub.path("valueCode"));
                case "doc-needed" -> addIfPresent(docNeeded, sub.path("valueCode"));
                case "info-needed" -> addIfPresent(infoNeeded, sub.path("valueCode"));
                case "date" -> date = textOrNull(sub.path("valueDate"));
                case "coverage-assertion-id", "identifier" -> {
                    if (assertionId == null || "coverage-assertion-id".equals(sub.path("url").asText())) {
                        assertionId = textOrNull(sub.path("valueString"));
                    }
                }
                case "questionnaire" -> addIfPresent(questionnaires, sub.path("valueCanonical"));
                case "satisfied-pa-id" -> satisfiedPaId = textOrNull(sub.path("valueString"));
                default -> { /* billingCode, reason, detail, dependency, contact: see extension() */ }
            }
        }
        return new CoverageInformation(reference, coverage, covered, paNeeded, List.copyOf(docNeeded),
                List.copyOf(infoNeeded), date, assertionId, satisfiedPaId, List.copyOf(questionnaires), ext);
    }

    private static String textOrNull(JsonNode node) {
        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private static void addIfPresent(List<String> list, JsonNode node) {
        String value = textOrNull(node);
        if (value != null) {
            list.add(value);
        }
    }
}
