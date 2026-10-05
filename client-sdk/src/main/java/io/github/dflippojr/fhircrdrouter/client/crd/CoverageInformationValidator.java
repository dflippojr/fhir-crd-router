package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks one CRD {@code ext-coverage-information} extension against the Da Vinci
 * CRD 2.2.1 profile and reports what is wrong in plain language.
 *
 * <p>Rules come from the published StructureDefinition
 * <a href="http://hl7.org/fhir/us/davinci-crd/STU2.2/StructureDefinition-ext-coverage-information.html">
 * {@code http://hl7.org/fhir/us/davinci-crd/StructureDefinition/ext-coverage-information}</a>,
 * version 2.2.1 (package {@code hl7.fhir.us.davinci-crd#2.2.1}):
 * <ul>
 *   <li>sub-extension cardinality: {@code coverage}, {@code covered}, {@code date} and
 *       {@code coverage-assertion-id} are 1..1; {@code pa-needed}, {@code satisfied-pa-id} and
 *       {@code expiry-date} are 0..1;</li>
 *   <li>each sub-extension's value type ({@code valueCode}, {@code valueDate}, ...);</li>
 *   <li>required bindings for {@code covered} (coverageInfo), {@code pa-needed} (coveragePaDetail),
 *       {@code doc-needed} (AdditionalDocumentation), {@code doc-purpose} (DocReason) and
 *       {@code info-needed} (informationNeeded);</li>
 *   <li>FHIR {@code date} format for {@code date} and {@code expiry-date};</li>
 *   <li>{@code coverage} is a Reference to a Coverage;</li>
 *   <li>invariants {@code crd-ci-q1} to {@code crd-ci-q9}.</li>
 * </ul>
 *
 * <p>The profile's sub-extension slicing is open, so unknown sub-extensions are allowed.
 * The one exception is {@code identifier}: the HL7 reference implementation sends it in place
 * of {@code coverage-assertion-id}, which is reported as a {@link Severity#WARNING} rather than
 * a missing-element {@link Severity#ERROR}. The internals of {@code detail}, {@code billingCode},
 * {@code contact} and {@code dependency} are not checked beyond their value type.
 *
 * <p>Two places where the invariant text and its FHIRPath differ: {@code crd-ci-q4} names
 * {@code noauth}, which is not a pa-needed code, so {@code no-auth} is checked as intended;
 * {@code crd-ci-q3} says "if and only if" but its expression only requires {@code info-needed}
 * when something is {@code conditional}, and that one direction is what is checked.
 *
 * <p>Parsing via {@link CoverageInformation#fromResource(JsonNode)} stays lenient; this class
 * only reports.
 */
public final class CoverageInformationValidator {

    /** How serious a {@link Violation} is. */
    public enum Severity { ERROR, WARNING }

    /**
     * One problem with an extension.
     *
     * @param path where the problem is, e.g. {@code extension[coverage-assertion-id]}
     * @param message plain-language description, citing the invariant key when there is one
     */
    public record Violation(Severity severity, String path, String message) {
        public Violation {
            Objects.requireNonNull(severity, "severity");
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(message, "message");
        }
    }

    static final String COVERAGE = "coverage";
    static final String COVERED = "covered";
    static final String PA_NEEDED = "pa-needed";
    static final String DOC_NEEDED = "doc-needed";
    static final String DOC_PURPOSE = "doc-purpose";
    static final String INFO_NEEDED = "info-needed";
    static final String REASON = "reason";
    static final String DATE = "date";
    static final String EXPIRY_DATE = "expiry-date";
    static final String COVERAGE_ASSERTION_ID = "coverage-assertion-id";
    static final String SATISFIED_PA_ID = "satisfied-pa-id";
    static final String QUESTIONNAIRE = "questionnaire";
    static final String LEGACY_IDENTIFIER = "identifier";

    private static final String CONDITIONAL = "conditional";
    private static final String INDETERMINATE = "indeterminate";
    private static final String REASON_SYSTEM = "http://hl7.org/fhir/us/davinci-crd/CodeSystem/temp";
    private static final String ROOT = "extension";

    private record Slice(int min, int max, String valueType, Set<String> codes) { }

    private static final int MANY = Integer.MAX_VALUE;

    private static final Map<String, Slice> SLICES = new LinkedHashMap<>();

    static {
        SLICES.put(COVERAGE, new Slice(1, 1, "valueReference", null));
        SLICES.put(COVERED, new Slice(1, 1, "valueCode",
                Set.of("not-covered", COVERED, CONDITIONAL, INDETERMINATE)));
        SLICES.put(PA_NEEDED, new Slice(0, 1, "valueCode",
                Set.of("no-auth", "auth-needed", "satisfied", "performpa", CONDITIONAL, INDETERMINATE)));
        SLICES.put(DOC_NEEDED, new Slice(0, MANY, "valueCode",
                Set.of("clinical", "admin", "patient", CONDITIONAL, INDETERMINATE)));
        SLICES.put(DOC_PURPOSE, new Slice(0, MANY, "valueCode",
                Set.of("withpa", "withclaim", "withorder", "retain-doc", "OTH")));
        SLICES.put(INFO_NEEDED, new Slice(0, MANY, "valueCode",
                Set.of("performer", "location", "timeframe", "contract-window", "detail-code", "OTH")));
        SLICES.put("billingCode", new Slice(0, MANY, "valueCoding", null));
        SLICES.put(REASON, new Slice(0, MANY, "valueCodeableConcept", null));
        SLICES.put("detail", new Slice(0, MANY, null, null));
        SLICES.put("dependency", new Slice(0, MANY, "valueReference", null));
        SLICES.put(QUESTIONNAIRE, new Slice(0, MANY, "valueCanonical", null));
        SLICES.put(DATE, new Slice(1, 1, "valueDate", null));
        SLICES.put(COVERAGE_ASSERTION_ID, new Slice(1, 1, "valueString", null));
        SLICES.put(SATISFIED_PA_ID, new Slice(0, 1, "valueString", null));
        SLICES.put("contact", new Slice(0, MANY, "valueContactDetail", null));
        SLICES.put(EXPIRY_DATE, new Slice(0, 1, "valueDate", null));
    }

    private static final Set<String> REASON_CODES = Set.of(
            "gold-card", "no-member-found", "no-active-coverage", "coverage-not-found", "auth-out-network", "technical");

    /** FHIR R4 {@code date} regex, with year, month and day captured for the calendar check. */
    private static final Pattern FHIR_DATE = Pattern.compile(
            "([0-9]([0-9]([0-9][1-9]|[1-9]0)|[1-9]00)|[1-9]000)(-(0[1-9]|1[0-2])(-(0[1-9]|[1-2][0-9]|3[0-1]))?)?");

    /** Relative, absolute or contained reference whose target is a Coverage. */
    private static final Pattern COVERAGE_REFERENCE = Pattern.compile(
            "(.*/)?Coverage/[A-Za-z0-9\\-.]{1,64}(/_history/[A-Za-z0-9\\-.]{1,64})?|#.+");

    private CoverageInformationValidator() { }

    /** Validates the raw extension a {@link CoverageInformation} was parsed from. */
    public static List<Violation> validate(CoverageInformation info) {
        Objects.requireNonNull(info, "info");
        return validate(info.extension());
    }

    /**
     * Validates one {@code ext-coverage-information} extension (the object with {@code url} and
     * {@code extension}, not the resource carrying it).
     *
     * @return violations in rule order; empty when the extension conforms
     */
    public static List<Violation> validate(JsonNode extension) {
        List<Violation> violations = new ArrayList<>();
        if (extension == null || !extension.isObject()) {
            violations.add(error(ROOT, "coverage-information must be a JSON object"));
            return violations;
        }
        checkRoot(extension, violations);

        Map<String, List<JsonNode>> byUrl = groupByUrl(extension, violations);
        for (Map.Entry<String, Slice> slice : SLICES.entrySet()) {
            checkSlice(slice.getKey(), slice.getValue(), byUrl, violations);
        }
        checkInvariants(byUrl, violations);
        return violations;
    }

    private static void checkRoot(JsonNode extension, List<Violation> violations) {
        String url = extension.path("url").asText(null);
        if (!CoverageInformation.EXTENSION_URL.equals(url)) {
            violations.add(error("url", "url must be " + CoverageInformation.EXTENSION_URL + ", got: " + url));
        }
        for (Iterator<String> names = extension.fieldNames(); names.hasNext(); ) {
            String name = names.next();
            if (name.startsWith("value")) {
                violations.add(error(name, "coverage-information is a complex extension and must not have a "
                        + name + "; put values in sub-extensions"));
            }
        }
    }

    private static Map<String, List<JsonNode>> groupByUrl(JsonNode extension, List<Violation> violations) {
        Map<String, List<JsonNode>> byUrl = new LinkedHashMap<>();
        JsonNode subs = extension.path(ROOT);
        if (!subs.isArray()) {
            violations.add(error(ROOT, "coverage-information has no sub-extensions"));
            return byUrl;
        }
        for (JsonNode sub : subs) {
            byUrl.computeIfAbsent(sub.path("url").asText(""), k -> new ArrayList<>()).add(sub);
        }
        return byUrl;
    }

    private static void checkSlice(String url, Slice slice, Map<String, List<JsonNode>> byUrl,
                                   List<Violation> violations) {
        List<JsonNode> subs = byUrl.getOrDefault(url, List.of());
        String path = path(url);
        if (subs.size() < slice.min()) {
            missing(url, path, byUrl, violations);
        } else if (subs.size() > slice.max()) {
            violations.add(error(path, url + " may appear at most once, found " + subs.size()));
        }
        for (JsonNode sub : subs) {
            checkValue(url, slice, sub, path, violations);
        }
    }

    private static void missing(String url, String path, Map<String, List<JsonNode>> byUrl,
                                List<Violation> violations) {
        if (COVERAGE_ASSERTION_ID.equals(url) && byUrl.containsKey(LEGACY_IDENTIFIER)) {
            violations.add(warning(path(LEGACY_IDENTIFIER), "identifier is the pre-2.x name for "
                    + "coverage-assertion-id; CRD 2.2.1 requires the url coverage-assertion-id"));
        } else {
            violations.add(error(path, url + " is required"));
        }
    }

    private static void checkValue(String url, Slice slice, JsonNode sub, String path, List<Violation> violations) {
        if (slice.valueType() == null) {
            return;
        }
        JsonNode value = sub.get(slice.valueType());
        if (value == null || value.isNull()) {
            violations.add(error(path, url + " must have a " + slice.valueType()
                    + otherValue(sub).map(found -> ", found " + found).orElse("")));
            return;
        }
        if (slice.codes() != null && !slice.codes().contains(value.asText())) {
            violations.add(error(path, url + " code '" + value.asText() + "' is not one of "
                    + String.join(", ", slice.codes().stream().sorted().toList())));
        } else if (DATE.equals(url) || EXPIRY_DATE.equals(url)) {
            checkDate(url, value.asText(), path, violations);
        } else if (COVERAGE.equals(url)) {
            checkCoverageReference(value, path, violations);
        }
    }

    private static Optional<String> otherValue(JsonNode sub) {
        for (Iterator<String> names = sub.fieldNames(); names.hasNext(); ) {
            String name = names.next();
            if (name.startsWith("value")) {
                return Optional.of(name);
            }
        }
        return Optional.empty();
    }

    private static void checkDate(String url, String text, String path, List<Violation> violations) {
        Matcher m = FHIR_DATE.matcher(text);
        boolean valid = m.matches();
        if (valid && m.group(7) != null) {
            try {
                LocalDate.parse(text);
            } catch (DateTimeException e) {
                valid = false;
            }
        }
        if (!valid) {
            violations.add(error(path, url + " '" + text + "' is not a FHIR date (YYYY, YYYY-MM or YYYY-MM-DD)"));
        }
    }

    private static void checkCoverageReference(JsonNode value, String path, List<Violation> violations) {
        JsonNode reference = value.get("reference");
        if (reference == null || reference.isNull()) {
            String type = value.path("type").asText(null);
            if (type != null && !"Coverage".equals(type)) {
                violations.add(error(path, "coverage must reference a Coverage, got type " + type));
            } else if (!value.has("identifier")) {
                violations.add(error(path, "coverage valueReference has no reference or identifier"));
            }
            return;
        }
        if (!COVERAGE_REFERENCE.matcher(reference.asText()).matches()) {
            violations.add(error(path, "coverage must reference a Coverage (Coverage/[id]), got: "
                    + reference.asText()));
        }
    }

    private static void checkInvariants(Map<String, List<JsonNode>> byUrl, List<Violation> violations) {
        List<String> covered = codes(byUrl, COVERED);
        List<String> paNeeded = codes(byUrl, PA_NEEDED);
        List<String> docNeeded = codes(byUrl, DOC_NEEDED);
        List<String> docPurpose = codes(byUrl, DOC_PURPOSE);
        List<String> infoNeeded = codes(byUrl, INFO_NEEDED);
        boolean hasReason = byUrl.containsKey(REASON);

        if (byUrl.containsKey(QUESTIONNAIRE) && !byUrl.containsKey(DOC_NEEDED)) {
            violations.add(error(path(QUESTIONNAIRE), "questionnaire is only allowed when doc-needed is present "
                    + "(crd-ci-q1)"));
        }
        if (covered.contains("not-covered") && byUrl.containsKey(PA_NEEDED)) {
            violations.add(error(path(PA_NEEDED), "pa-needed must be absent when covered is not-covered "
                    + "(crd-ci-q2)"));
        }
        if (anyOf(CONDITIONAL, covered, paNeeded, docNeeded) && !byUrl.containsKey(INFO_NEEDED)) {
            violations.add(error(path(INFO_NEEDED), "info-needed is required when covered, pa-needed or "
                    + "doc-needed is conditional (crd-ci-q3)"));
        }
        if ((paNeeded.contains("satisfied") || paNeeded.contains("no-auth")) && docPurpose.contains("withpa")) {
            violations.add(error(path(DOC_PURPOSE), "doc-purpose cannot be withpa when pa-needed is "
                    + paNeeded.get(0) + " (crd-ci-q4)"));
        }
        boolean satisfied = paNeeded.contains("satisfied");
        if (satisfied != byUrl.containsKey(SATISFIED_PA_ID)) {
            violations.add(error(path(SATISFIED_PA_ID), satisfied
                    ? "satisfied-pa-id is required when pa-needed is satisfied (crd-ci-q5)"
                    : "satisfied-pa-id is only allowed when pa-needed is satisfied (crd-ci-q5)"));
        }
        if (infoNeeded.contains("OTH") && !hasReason) {
            violations.add(error(path(REASON), "reason is required when info-needed is OTH (crd-ci-q6)"));
        }
        checkReasonText(byUrl, violations);
        if (!docPurpose.isEmpty() && !hasReason) {
            violations.add(error(path(REASON), "reason is required when doc-purpose is present (crd-ci-q8)"));
        }
        if (anyOf(INDETERMINATE, covered, paNeeded, docNeeded) && !hasReason) {
            violations.add(error(path(REASON), "reason is required to explain an indeterminate covered, pa-needed "
                    + "or doc-needed (crd-ci-q9)"));
        }
    }

    /** crd-ci-q7: a reason with no coding from coverageAssertionReasons needs text. */
    private static void checkReasonText(Map<String, List<JsonNode>> byUrl, List<Violation> violations) {
        for (JsonNode reason : byUrl.getOrDefault(REASON, List.of())) {
            JsonNode concept = reason.path("valueCodeableConcept");
            if (!concept.isObject() || concept.hasNonNull("text")) {
                continue;
            }
            boolean inValueSet = false;
            for (JsonNode coding : concept.path("coding")) {
                inValueSet |= REASON_SYSTEM.equals(coding.path("system").asText())
                        && REASON_CODES.contains(coding.path("code").asText());
            }
            if (!inValueSet) {
                violations.add(error(path(REASON), "reason needs text when its coding is not from the "
                        + "coverageAssertionReasons value set (crd-ci-q7)"));
            }
        }
    }

    private static List<String> codes(Map<String, List<JsonNode>> byUrl, String url) {
        List<String> codes = new ArrayList<>();
        for (JsonNode sub : byUrl.getOrDefault(url, List.of())) {
            JsonNode code = sub.get("valueCode");
            if (code != null && code.isTextual()) {
                codes.add(code.asText());
            }
        }
        return codes;
    }

    @SafeVarargs
    private static boolean anyOf(String code, List<String>... lists) {
        for (List<String> list : lists) {
            if (list.contains(code)) {
                return true;
            }
        }
        return false;
    }

    private static String path(String url) {
        return ROOT + "[" + url + "]";
    }

    private static Violation error(String path, String message) {
        return new Violation(Severity.ERROR, path, message);
    }

    private static Violation warning(String path, String message) {
        return new Violation(Severity.WARNING, path, message);
    }
}
