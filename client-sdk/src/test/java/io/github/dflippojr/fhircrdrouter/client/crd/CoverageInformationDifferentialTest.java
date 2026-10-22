package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformationValidator.Severity;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformationValidator.Violation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Differential test: {@link CoverageInformationValidator}'s verdict on each case in
 * {@code coverage-information/cases} must match the official HL7 FHIR validator's verdict, recorded
 * in {@code official-verdicts.json} by {@code fhir-validator/run.sh} (CI's {@code fhir-validator} job
 * regenerates it and fails if it changes).
 *
 * <p>A verdict is "valid" when there are no errors; our {@link Severity#WARNING}s do not count. When
 * the official validator reports a CRD invariant ({@code crd-ci-q1} to {@code crd-ci-q9}), we must
 * report the same one. Cases in {@code known-differences.json} are disagreements that are deliberate
 * (DECISIONS.md) or open bugs; they must still disagree, so a fixed bug cannot leave a stale entry. An
 * entry with a {@code warning} path is a deliberate leniency: we must report a {@link Severity#WARNING}
 * there, so the leniency is a warning and not silence.
 */
class CoverageInformationDifferentialTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DIR = "/coverage-information/";
    private static final Pattern INVARIANT = Pattern.compile("crd-ci-q\\d");

    private static final JsonNode OFFICIAL = read("official-verdicts.json");
    private static final JsonNode KNOWN = read("known-differences.json");

    static Stream<String> cases() {
        List<String> names = new ArrayList<>();
        OFFICIAL.path("verdicts").fieldNames().forEachRemaining(names::add);
        return names.stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void verdictMatchesOfficialValidator(String name) {
        JsonNode official = OFFICIAL.path("verdicts").path(name);
        List<Violation> ours = CoverageInformationValidator.validate(extension(name));
        boolean oursValid = ours.stream().noneMatch(v -> v.severity() == Severity.ERROR);
        boolean officialValid = official.path("valid").asBoolean();

        JsonNode known = KNOWN.get(name);
        if (known != null) {
            assertEquals(known.path("ours").asText(), oursValid ? "valid" : "invalid",
                    () -> name + " is a known difference with our verdict " + known.path("ours").asText()
                            + ", but we now say otherwise: " + ours);
            assertNotEquals(officialValid, oursValid, () -> name + " now agrees with the official validator; "
                    + "remove it from known-differences.json (and close its issue or DECISIONS.md entry)");
            if (known.has("warning")) {
                String path = known.path("warning").asText();
                assertTrue(ours.stream().anyMatch(v -> v.severity() == Severity.WARNING && v.path().equals(path)),
                        () -> name + " should be a WARNING at " + path + ", ours " + ours);
            }
            return;
        }
        assertEquals(officialValid, oursValid, () -> name + ": official " + (officialValid ? "valid" : "invalid")
                + " " + official.path("errors") + ", ours " + ours);
        assertEquals(officialInvariants(official.path("errors")), invariants(ours),
                () -> name + ": different crd-ci invariants reported; official " + official.path("errors")
                        + ", ours " + ours);
    }

    @Test
    void verdictsWereRecordedForThePinnedValidatorAndIg() {
        assertFalse(OFFICIAL.path("validator").asText().isEmpty());
        assertEquals("hl7.fhir.us.davinci-crd#2.2.1", OFFICIAL.path("ig").asText());
    }

    @Test
    void everyKnownDifferenceIsACorpusCaseWithAReason() {
        Set<String> cases = new TreeSet<>(cases().toList());
        KNOWN.fieldNames().forEachRemaining(name -> {
            if (name.startsWith("_")) {
                return;
            }
            assertTrue(cases.contains(name), () -> name + " in known-differences.json is not a corpus case");
            assertFalse(KNOWN.path(name).path("why").asText().isBlank(), () -> name + " has no reason");
        });
    }

    @Test
    void corpusIsLargeEnoughToMeanSomething() {
        long valid = cases().filter(name -> OFFICIAL.path("verdicts").path(name).path("valid").asBoolean()).count();
        long invalid = cases().count() - valid;
        assertTrue(valid >= 5 && invalid >= 30, () -> valid + " valid and " + invalid + " invalid cases");
    }

    private static JsonNode extension(String name) {
        JsonNode resource = read("cases/" + name + ".json");
        for (JsonNode ext : resource.path("extension")) {
            if (CoverageInformation.EXTENSION_URL.equals(ext.path("url").asText())) {
                return ext;
            }
        }
        throw new AssertionError(name + " has no coverage-information extension");
    }

    private static Set<String> officialInvariants(JsonNode errors) {
        Set<String> keys = new TreeSet<>();
        for (JsonNode error : errors) {
            keys.addAll(invariants(error.path("messageId").asText()));
        }
        return keys;
    }

    private static Set<String> invariants(List<Violation> violations) {
        Set<String> keys = new TreeSet<>();
        for (Violation v : violations) {
            if (v.severity() == Severity.ERROR) {
                keys.addAll(invariants(v.message()));
            }
        }
        return keys;
    }

    private static Set<String> invariants(String text) {
        Set<String> keys = new TreeSet<>();
        Matcher m = INVARIANT.matcher(text);
        while (m.find()) {
            keys.add(m.group());
        }
        return keys;
    }

    private static JsonNode read(String path) {
        try (InputStream in = CoverageInformationDifferentialTest.class.getResourceAsStream(DIR + path)) {
            assertNotNull(in, "missing test resource " + DIR + path);
            return MAPPER.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
