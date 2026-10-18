package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.fhircrdrouter.client.CdsDiscoveryValidator;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.client.CdsServiceDescriptor;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PrefetchTemplates;
import io.github.dflippojr.fhircrdrouter.client.auth.Jwks;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Runs this library's {@link CdsHooksClient} against the Da Vinci CRD Client
 * v2.2.1 suite of the Inferno CRD test kit, where Inferno plays the CRD
 * server and judges the client's requests. Skipped unless
 * {@code INFERNO_BASE_URL} is set; see docs/inferno.md for how to start the
 * kit, e.g.:
 *
 * <pre>
 * INFERNO_BASE_URL=http://localhost:18080 ./mvnw -pl client-sdk -am test -Dtest=InfernoCrdClientSuiteTest
 * </pre>
 *
 * <p>Each hook group is run with the kit's own conformant CRD 2.2.1 request
 * bodies (src/test/resources/inferno), sent through {@code callHook} with a
 * CDS Hooks client JWT. Inferno's verdict on every test is compared with
 * {@code expected-results.json}, one dynamic test per Inferno test, and the
 * full run is written to {@code target/inferno/}.
 */
@EnabledIfEnvironmentVariable(named = "INFERNO_BASE_URL", matches = ".+")
class InfernoCrdClientSuiteTest {

    private static final String SUITE = "crd_client_v221";
    private static final List<String> HOOKS = List.of("appointment-book", "encounter-start",
            "encounter-discharge", "order-select", "order-dispatch", "order-sign");
    // Organization ids the fixtures' Coverage.payor resolves to, per simulated service.
    private static final String COMPLETE_PAYER = "crd221-demo-payer-complete-prefetch";
    private static final String SUBSET_PAYER = "crd221-demo-payer-subset-prefetch";
    private static final String RESPONSE_TYPES =
            "[\"coverage_information\",\"external_reference\",\"instructions\"]";
    // The first runs after a cold start wait while the HL7 validator loads its IG packages.
    private static final Duration RUN_TIMEOUT = Duration.ofMinutes(30);

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final String inferno = stripSlash(System.getenv("INFERNO_BASE_URL"));
    private final String suiteBase = inferno + "/custom/" + SUITE;
    private final Map<String, String> secrets = new LinkedHashMap<>();
    /** The last hook response body exactly as received, to check what the client decoded from it. */
    private final AtomicReference<String> lastHookResponse = new AtomicReference<>();
    private final CdsHooksClient client = new CdsHooksClient(new MapCredentials(secrets),
            Duration.ofSeconds(60), Duration.ofSeconds(5), exchange -> {
                if (exchange.phase() == PayerCallPhase.HOOK) {
                    lastHookResponse.set(exchange.responseBody());
                }
            });

    @TestFactory
    Stream<DynamicTest> clientSuiteVerdictsMatchTheRecordedResults() throws Exception {
        KeyPair key = TestKeys.ec("secp384r1");
        secrets.put("inferno-key", TestKeys.privateKeyPem(key));
        String jwks = Jwks.builder().add("inferno-key-1", key.getPublic()).toJson();
        List<String> harnessNotes = new ArrayList<>();

        // Inferno checks each JWT's exp when it analyses the group, not when the request arrived. On a cold
        // start the HL7 validator loads its packages for longer than the token lives, so warm it up in a
        // throwaway session (with its own issuer, which is how Inferno routes requests) before the judged one.
        Session warmUp = openSession();
        Invoker warmUpInvoker = register(warmUp, "fhir-crd-router-warm-up-" + UUID.randomUUID(), jwks,
                new ArrayList<>());
        runHookGroup(warmUp, warmUpInvoker, "encounter-start");

        Session session = openSession();
        Invoker invoker = register(session, "fhir-crd-router-" + UUID.randomUUID(), jwks, harnessNotes);
        // 1.2.x: one group per hook, each sent the kit's requests for that hook to both services.
        for (String hook : HOOKS) {
            runHookGroup(session, invoker, hook);
        }
        // 1.4 Cross Hook: its first subgroup takes more invocations; the rest analyse every request received.
        String run = startRun(session.id(), session.group("1.4"), Map.of(
                "cds_jwt_iss", invoker.issuer(),
                "cross_hooks_response_approach", "mocked",
                "cross_hooks_selected_response_types", RESPONSE_TYPES));
        invokeAndFinish(session.id(), run, invoker, HOOKS);

        Map<String, Outcome> actual = results(session);
        writeReport(actual, harnessNotes);
        JsonNode expected = fixture("expected-results.json").path("tests");

        List<DynamicTest> tests = new ArrayList<>();
        for (Map.Entry<String, Outcome> entry : actual.entrySet()) {
            Outcome outcome = entry.getValue();
            tests.add(DynamicTest.dynamicTest(entry.getKey() + " " + outcome.title(), () -> {
                JsonNode want = expected.path(entry.getKey());
                if (want.isMissingNode()) {
                    fail("Inferno test " + entry.getKey() + " (" + outcome.title() + ") is not in "
                            + "expected-results.json; got " + outcome.result() + ": " + outcome.message());
                }
                assertEquals(want.path("result").asText(), outcome.result(),
                        "Inferno " + entry.getKey() + " " + outcome.title() + ": " + outcome.message()
                                + " (recorded reason: " + want.path("reason").asText("none") + ")");
            }));
        }
        Iterator<String> recorded = expected.fieldNames();
        while (recorded.hasNext()) {
            String id = recorded.next();
            if (!actual.containsKey(id)) {
                tests.add(DynamicTest.dynamicTest(id + " still exists",
                        () -> fail("expected-results.json lists " + id + " but Inferno did not run it")));
            }
        }
        return tests.stream();
    }

    private Session openSession() throws Exception {
        JsonNode created = postJson("/api/test_sessions", mapper.createObjectNode()
                .put("test_suite_id", SUITE)
                .set("suite_options", mapper.createArrayNode().add(mapper.createObjectNode()
                        .put("id", "us_core_version").put("value", "us_core_3"))));
        Map<String, String> shortIds = new LinkedHashMap<>();
        Map<String, String> titles = new LinkedHashMap<>();
        index(created.path("test_suite").path("test_groups"), shortIds, titles);
        return new Session(created.path("id").asText(), shortIds, titles);
    }

    /**
     * Runs 1.1 Registration for {@code issuer}, then discovers both simulated services. The two
     * ConnectionRecords are this library's registration of Inferno's services, so that attestation is true.
     */
    private Invoker register(Session session, String issuer, String jwks, List<String> notes) throws Exception {
        String run = startRun(session.id(), session.group("1.1"), Map.of(
                "cds_jwt_iss", issuer,
                "cds_jwk_set", jwks,
                "complete_prefetch_service_organization_id", COMPLETE_PAYER,
                "subset_prefetch_service_organization_id", SUBSET_PAYER));
        resumeUntilDone(session.id(), run, "attest_true_url");
        ConnectionRecord complete = record("INFERNO-COMPLETE", suiteBase, issuer);
        ConnectionRecord subset = record("INFERNO-SUBSET", suiteBase + "/prefetch-subset", issuer);
        return new Invoker(issuer, complete, subset, servicesByHook(complete, notes), servicesByHook(subset, notes),
                fixture("complete-prefetch-requests.json"), fixture("subset-prefetch-requests.json"), notes);
    }

    private void runHookGroup(Session session, Invoker invoker, String hook) throws Exception {
        String prefix = hook.replace('-', '_');
        String run = startRun(session.id(), session.hookGroup(hook), Map.of(
                "cds_jwt_iss", invoker.issuer(),
                prefix + "_response_approach", "mocked",
                prefix + "_selected_response_types", RESPONSE_TYPES));
        invokeAndFinish(session.id(), run, invoker, List.of(hook));
    }

    private void invokeAndFinish(String session, String run, Invoker invoker, List<String> hooks) throws Exception {
        awaitStatus(run, "waiting");
        for (String hook : hooks) {
            invoker.invoke(hook);
        }
        get(sessionValue(session, "continuation_url"));
        // A library has no user interface, so it cannot attest that cards were displayed to a user.
        resumeUntilDone(session, run, "attest_false_url");
    }

    /** Sends the kit's request bodies for a hook to the complete and the subset prefetch services. */
    private final class Invoker {
        private final String issuer;
        private final ConnectionRecord complete;
        private final ConnectionRecord subset;
        private final Map<String, CdsServiceDescriptor> completeServices;
        private final Map<String, CdsServiceDescriptor> subsetServices;
        private final JsonNode completeBodies;
        private final JsonNode subsetBodies;
        private final List<String> notes;

        Invoker(String issuer, ConnectionRecord complete, ConnectionRecord subset,
                Map<String, CdsServiceDescriptor> completeServices, Map<String, CdsServiceDescriptor> subsetServices,
                JsonNode completeBodies, JsonNode subsetBodies, List<String> notes) {
            this.issuer = issuer;
            this.complete = complete;
            this.subset = subset;
            this.completeServices = completeServices;
            this.subsetServices = subsetServices;
            this.completeBodies = completeBodies;
            this.subsetBodies = subsetBodies;
            this.notes = notes;
        }

        String issuer() {
            return issuer;
        }

        void invoke(String hook) {
            for (JsonNode body : completeBodies.path(hook)) {
                notes.add(call(complete, completeServices.get(hook), body));
            }
            for (JsonNode body : subsetBodies.path(hook)) {
                notes.add(call(subset, subsetServices.get(hook), body));
            }
        }
    }

    private ConnectionRecord record(String payerId, String baseUrl, String issuer) {
        return ConnectionRecord.builder()
                .payerId(payerId)
                .displayName("Inferno CRD client suite simulated payer")
                .environment(Environment.SANDBOX)
                .baseUrl(baseUrl)
                .authType(AuthType.CDS_HOOKS_JWT)
                .clientId(issuer)
                .keyId("inferno-key-1")
                .credentialRef("inferno-key")
                .build();
    }

    /** Discovers a simulated service and checks it with this library's own discovery validator. */
    private Map<String, CdsServiceDescriptor> servicesByHook(ConnectionRecord record, List<String> notes) {
        List<CdsDiscoveryValidator.Violation> violations =
                CdsDiscoveryValidator.validate(client.discoverServicesRaw(record));
        notes.add("discovery " + record.baseUrl() + ": CdsDiscoveryValidator violations=" + violations);
        Map<String, CdsServiceDescriptor> byHook = new LinkedHashMap<>();
        for (CdsServiceDescriptor service : client.discoverServices(record)) {
            byHook.put(service.hook(), service);
        }
        assertTrue(byHook.keySet().containsAll(HOOKS), "Inferno advertises every CRD hook: " + byHook);
        return byHook;
    }

    private String call(ConnectionRecord record, CdsServiceDescriptor service, JsonNode body) {
        Map<String, Object> prefetch = new LinkedHashMap<>();
        body.path("prefetch").fields().forEachRemaining(e -> prefetch.put(e.getKey(),
                e.getValue().isNull() ? null : e.getValue()));
        JsonNode auth = body.path("fhirAuthorization");
        CdsHookRequest request = new CdsHookRequest(body.path("hook").asText(), UUID.randomUUID().toString(),
                body.path("fhirServer").asText(null),
                auth.isMissingNode() ? null : new CdsHookRequest.FhirAuthorization(
                        auth.path("access_token").asText(), auth.path("token_type").asText(null),
                        auth.path("expires_in").isNumber() ? auth.path("expires_in").asInt() : null,
                        auth.path("scope").asText(null), auth.path("subject").asText(null)),
                body.path("context"), prefetch);
        // The kit's prefetch is sent as is; this records which of the service's templates the SDK could expand.
        PrefetchTemplates.Expansion expansion = PrefetchTemplates.expand(service.prefetch(), request);
        lastHookResponse.set(null);
        CdsHookResponse response = client.callHook(record, service.id(), request);
        String decoded = ParsedResponseCheck.assertMatchesWire(lastHookResponse.get(), response);
        return "call " + service.id() + " at " + record.baseUrl() + ": " + decoded
                + "; PrefetchTemplates expands " + expansion.queries().keySet()
                + ", unresolved " + expansion.unresolved().keySet();
    }

    private JsonNode fixture(String name) throws IOException {
        try (InputStream in = getClass().getResourceAsStream("/inferno/" + name)) {
            assertNotNull(in, "missing fixture /inferno/" + name);
            String text = new String(in.readAllBytes()).replace("{{inferno}}", inferno);
            return mapper.readTree(text);
        }
    }

    private static void index(JsonNode groups, Map<String, String> shortIds, Map<String, String> titles) {
        for (JsonNode group : groups) {
            shortIds.put(group.path("short_id").asText(), group.path("id").asText());
            titles.put(group.path("id").asText(), group.path("title").asText());
            for (JsonNode test : group.path("tests")) {
                shortIds.put(test.path("short_id").asText(), test.path("id").asText());
                titles.put(test.path("id").asText(), test.path("title").asText());
            }
            index(group.path("test_groups"), shortIds, titles);
        }
    }

    private String startRun(String session, String groupId, Map<String, String> inputs) throws Exception {
        ArrayNode list = mapper.createArrayNode();
        inputs.forEach((name, value) -> list.addObject().put("name", name).put("value", value));
        ObjectNode body = mapper.createObjectNode().put("test_session_id", session).put("test_group_id", groupId);
        body.set("inputs", list);
        return postJson("/api/test_runs", body).path("id").asText();
    }

    /** Answers each wait the run reaches with the session output {@code resumeOutput}, until it is done. */
    private void resumeUntilDone(String session, String run, String resumeOutput) throws Exception {
        String seen = null;
        while (true) {
            String status = awaitStatus(run, "waiting", "done");
            if ("done".equals(status)) {
                return;
            }
            String url = sessionValue(session, resumeOutput);
            if (url.equals(seen)) {
                awaitStatus(run, "done", "waiting");
                continue;
            }
            seen = url;
            get(url);
        }
    }

    private String awaitStatus(String run, String... wanted) throws Exception {
        Instant deadline = Instant.now().plus(RUN_TIMEOUT);
        while (Instant.now().isBefore(deadline)) {
            String status = getJson("/api/test_runs/" + run).path("status").asText();
            for (String w : wanted) {
                if (w.equals(status)) {
                    return status;
                }
            }
            if ("cancelled".equals(status) || ("done".equals(status))) {
                fail("Inferno run " + run + " ended as " + status + " while waiting for " + List.of(wanted));
            }
            Thread.sleep(1000);
        }
        throw new AssertionError("Inferno run " + run + " did not reach " + List.of(wanted) + " in " + RUN_TIMEOUT);
    }

    private String sessionValue(String session, String name) throws Exception {
        for (JsonNode item : getJson("/api/test_sessions/" + session + "/session_data")) {
            if (name.equals(item.path("name").asText())) {
                return item.path("value").asText();
            }
        }
        throw new AssertionError("Inferno session has no output " + name);
    }

    private Map<String, Outcome> results(Session session) throws Exception {
        Map<String, String> byLongId = new LinkedHashMap<>();
        session.shortIds().forEach((shortId, id) -> byLongId.put(id, shortId));
        Map<String, String> titles = session.titles();
        Map<String, Outcome> out = new TreeMap<>(InfernoCrdClientSuiteTest::compareShortIds);
        for (JsonNode result : getJson("/api/test_sessions/" + session.id() + "/results")) {
            String testId = result.path("test_id").asText(null);
            if (testId == null) {
                continue;
            }
            List<String> messages = new ArrayList<>();
            for (JsonNode m : result.path("messages")) {
                if (!"info".equals(m.path("type").asText())) {
                    messages.add(m.path("type").asText() + ": " + m.path("message").asText());
                }
            }
            String message = result.path("result_message").asText("");
            if (!messages.isEmpty()) {
                message += (message.isEmpty() ? "" : " | ") + String.join(" | ", messages);
            }
            out.put(byLongId.getOrDefault(testId, testId),
                    new Outcome(titles.getOrDefault(testId, testId), result.path("result").asText(), message));
        }
        return out;
    }

    private void writeReport(Map<String, Outcome> results, List<String> notes) throws IOException {
        Path dir = Path.of("target", "inferno");
        Files.createDirectories(dir);
        ObjectNode report = mapper.createObjectNode();
        report.put("inferno", inferno);
        ArrayNode notesJson = report.putArray("harness");
        notes.forEach(notesJson::add);
        ObjectNode tests = report.putObject("tests");
        results.forEach((id, o) -> tests.putObject(id).put("title", o.title()).put("result", o.result())
                .put("message", o.message()));
        mapper.enable(SerializationFeature.INDENT_OUTPUT).writeValue(dir.resolve("results.json").toFile(), report);
        StringBuilder md = new StringBuilder("| Test | Title | Result | Message |\n|---|---|---|---|\n");
        results.forEach((id, o) -> md.append("| ").append(id).append(" | ").append(o.title()).append(" | ")
                .append(o.result()).append(" | ")
                .append(o.message().replace("|", "\\|").replace("\n", " ")).append(" |\n"));
        Files.writeString(dir.resolve("results.md"), md);
        notes.forEach(note -> System.out.println("Inferno harness: " + note));
    }

    private static int compareShortIds(String a, String b) {
        String[] x = a.split("\\.");
        String[] y = b.split("\\.");
        for (int i = 0; i < Math.min(x.length, y.length); i++) {
            int c = x[i].matches("\\d+") && y[i].matches("\\d+")
                    ? Integer.compare(Integer.parseInt(x[i]), Integer.parseInt(y[i])) : x[i].compareTo(y[i]);
            if (c != 0) {
                return c;
            }
        }
        return Integer.compare(x.length, y.length);
    }

    private JsonNode getJson(String path) throws Exception {
        return mapper.readTree(send(HttpRequest.newBuilder(URI.create(inferno + path)).GET()));
    }

    private JsonNode postJson(String path, JsonNode body) throws Exception {
        return mapper.readTree(send(HttpRequest.newBuilder(URI.create(inferno + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))));
    }

    /** Follows a resume link; Inferno answers with a redirect to its UI, which is not followed. */
    private void get(String url) throws Exception {
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(60)).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(response.statusCode() / 100 == 2 || response.statusCode() / 100 == 3,
                "GET " + url + " -> " + response.statusCode() + ": " + response.body());
    }

    private String send(HttpRequest.Builder request) throws Exception {
        HttpResponse<String> response = http.send(request.timeout(Duration.ofSeconds(60)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(response.statusCode() / 100 == 2,
                response.request().method() + " " + response.request().uri() + " -> " + response.statusCode()
                        + ": " + response.body());
        return response.body();
    }

    private static String stripSlash(String url) {
        return url == null || !url.endsWith("/") ? url : url.substring(0, url.length() - 1);
    }

    /** An Inferno test session and its suite's short ids ("1.2.3") and titles, by Inferno id. */
    private record Session(String id, Map<String, String> shortIds, Map<String, String> titles) {

        String group(String shortId) {
            return Optional.ofNullable(shortIds.get(shortId))
                    .orElseThrow(() -> new AssertionError("Inferno suite has no group " + shortId));
        }

        /** The 1.2.x group for a hook, found by title because the kit does not number hooks in a fixed order. */
        String hookGroup(String hook) {
            return shortIds.entrySet().stream()
                    .filter(e -> e.getKey().matches("1\\.2\\.\\d+") && hook.equals(titles.get(e.getValue())))
                    .map(Map.Entry::getValue).findFirst()
                    .orElseThrow(() -> new AssertionError("Inferno suite has no 1.2.x group for " + hook));
        }
    }

    private record Outcome(String title, String result, String message) { }

    private record MapCredentials(Map<String, String> secrets) implements CredentialProvider {
        @Override public Optional<String> resolve(String credentialRef) {
            return Optional.ofNullable(secrets.get(credentialRef));
        }
        @Override public void put(String credentialRef, String secretValue) { secrets.put(credentialRef, secretValue); }
        @Override public void remove(String credentialRef) { secrets.remove(credentialRef); }
    }
}
