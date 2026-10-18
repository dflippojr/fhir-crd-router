package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.fhircrdrouter.client.testsupport.JsonArbitraries;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Received;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Whatever a payer or its token endpoint sends back, the only exceptions that escape the client are
 * the documented ones: {@link RouterException} and its subclass {@link PayerCallException}. Never a
 * NullPointerException, DateTimeException or ClassCastException (the #68, #69 and #70 class), and
 * {@link CdsHooksClient#verify} reports instead of throwing.
 */
class PayerResponsePropertiesTest {

    /** Fixed so CI is reproducible; jqwik prints the seed and the shrunk sample on failure. */
    private static final String SEED = "98068";
    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern B64TOKEN = Pattern.compile("[A-Za-z0-9._~+/-]+=*");
    private static final String SECRET = "client-secret";
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final CredentialProvider CREDENTIALS = new CredentialProvider() {
        @Override public Optional<String> resolve(String credentialRef) { return Optional.of(SECRET); }
        @Override public void put(String credentialRef, String secretValue) { }
        @Override public void remove(String credentialRef) { }
    };
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance",
            Map.of("patientId", "p"), null);

    private static LoopbackPayer payer;

    @BeforeContainer
    static void start() {
        payer = new LoopbackPayer();
    }

    @AfterContainer
    static void stop() {
        payer.close();
    }

    @Property(seed = SEED)
    void discoveryFailsOnlyWithDocumentedExceptions(@ForAll("discoveryBodies") String body,
                                                    @ForAll("statuses") int status) {
        payer.reset(request -> new Reply(status, body));
        ConnectionRecord record = unauthenticated();
        CdsHooksClient client = new CdsHooksClient(HTTP, CREDENTIALS);

        documented(() -> client.discoverServices(record))
                .ifPresent(services -> services.forEach(service -> assertNotNull(service)));
        documented(() -> client.discoverServicesRaw(record));
        assertNotNull(client.verify(record));
    }

    @Property(seed = SEED)
    void hookResponsesFailOnlyWithDocumentedExceptions(@ForAll("hookBodies") String body,
                                                       @ForAll("statuses") int status) {
        payer.reset(request -> new Reply(status, body));
        ConnectionRecord record = unauthenticated();
        CdsHooksClient client = new CdsHooksClient(HTTP, CREDENTIALS);

        documented(() -> client.callHook(record, "svc", REQUEST)).ifPresent(response -> {
            response.cards().forEach(card -> assertNotNull(card));
            response.systemActions().forEach(action -> assertNotNull(action));
        });
        documented(() -> client.callHookRaw(record, "svc", REQUEST));
    }

    /**
     * Any token response, including any JSON type for {@code access_token} and {@code expires_in}:
     * the payer either receives a bearer token that is exactly the non-blank string the token
     * endpoint issued, or is never called and the caller gets a documented exception. String
     * tokens here are mostly RFC 6750 {@code b64token}s; the any-text property below covers the rest.
     */
    @Property(seed = SEED)
    void tokenResponsesYieldTheIssuedTokenOrADocumentedFailure(@ForAll("tokenBodies") String tokenBody,
                                                               @ForAll("statuses") int tokenStatus) {
        checkTokenResponse(tokenBody, tokenStatus);
    }

    /** As above, with any text as the token: one that is not a b64token is never sent or cached (#111). */
    @Property(seed = SEED)
    void anyTokenTextYieldsTheIssuedTokenOrADocumentedFailure(@ForAll("anyTextTokenBodies") String tokenBody,
                                                              @ForAll("statuses") int tokenStatus) {
        checkTokenResponse(tokenBody, tokenStatus);
    }

    private static void checkTokenResponse(String tokenBody, int tokenStatus) {
        payer.reset(request -> request.rawPath().equals("/token")
                ? new Reply(tokenStatus, tokenBody)
                : new Reply(200, "{\"services\":[],\"cards\":[]}"));
        ConnectionRecord record = ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl(payer.origin()).authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint(payer.origin() + "/token").clientId("client").credentialRef("ref").build();
        CdsHooksClient client = new CdsHooksClient(HTTP, CREDENTIALS);

        Optional<?> discovery = documented(() -> client.discoverServices(record));
        Optional<?> hook = documented(() -> client.callHook(record, "svc", REQUEST));
        assertNotNull(client.verify(record));

        Optional<String> issued = usableToken(tokenStatus, tokenBody);
        List<Received> payerCalls = payer.received().stream().filter(r -> !r.rawPath().equals("/token")).toList();
        if (issued.isEmpty()) {
            assertTrue(discovery.isEmpty() && hook.isEmpty(), "succeeded without a usable token");
            assertTrue(payerCalls.isEmpty(), "payer called without a usable token: " + payerCalls);
        } else {
            assertTrue(discovery.isPresent() && hook.isPresent(), "failed with a usable token");
            assertFalse(payerCalls.isEmpty());
            payerCalls.forEach(call -> assertEquals("Bearer " + issued.get(), call.authorization()));
        }
    }

    /** The token the SDK should accept: a JSON string {@code access_token} that is a b64token, in a 2xx response. */
    private static Optional<String> usableToken(int status, String body) {
        return status / 100 == 2 ? textToken(body).filter(token -> B64TOKEN.matcher(token).matches()) : Optional.empty();
    }

    /** The body's {@code access_token} when the body is JSON and that field is a string. */
    private static Optional<String> textToken(String body) {
        try {
            JsonNode json = MAPPER.readTree(body);
            JsonNode token = json == null ? null : json.get("access_token");
            return token != null && token.isTextual() ? Optional.of(token.textValue()) : Optional.empty();
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /** Runs {@code call}; a documented failure is empty, anything else escapes and fails the property. */
    private static <T> Optional<T> documented(Supplier<T> call) {
        try {
            return Optional.of(call.get());
        } catch (RouterException e) {
            assertNotNull(e.getMessage());
            return Optional.empty();
        }
    }

    private static ConnectionRecord unauthenticated() {
        return ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl(payer.origin()).authType(AuthType.NONE).build();
    }

    @Provide
    Arbitrary<Integer> statuses() {
        return Arbitraries.frequencyOf(
                Tuple.of(6, Arbitraries.just(200)),
                Tuple.of(1, Arbitraries.of(201, 400, 401, 403, 404, 429, 500, 502, 503)));
    }

    @Provide
    Arbitrary<String> discoveryBodies() {
        Arbitrary<JsonNode> prefetch = Arbitraries.maps(JsonArbitraries.text(),
                Arbitraries.oneOf(JsonArbitraries.text().map(NODES::textNode), JsonArbitraries.scalar()))
                .ofMaxSize(3).map(JsonArbitraries::object);
        Arbitrary<JsonNode> service = Arbitraries.oneOf(
                JsonArbitraries.objectWith(List.of("hook", "id", "title", "description", "prefetch"), 2),
                Combinators.combine(JsonArbitraries.objectWith(List.of("hook", "id", "title", "description"), 1),
                        prefetch).as((node, p) -> (JsonNode) ((ObjectNode) node.deepCopy()).set("prefetch", p)),
                JsonArbitraries.scalar());
        return bodies(wrapper("services", service));
    }

    @Provide
    Arbitrary<String> hookBodies() {
        Arbitrary<JsonNode> card = Arbitraries.oneOf(
                JsonArbitraries.objectWith(List.of("uuid", "summary", "detail", "indicator", "source",
                        "suggestions", "selectionBehavior", "links"), 2),
                JsonArbitraries.scalar());
        Arbitrary<JsonNode> action = Arbitraries.oneOf(
                JsonArbitraries.objectWith(List.of("type", "description", "resource", "resourceId"), 2),
                JsonArbitraries.scalar());
        Arbitrary<JsonNode> shaped = Combinators.combine(wrapper("cards", card), wrapper("systemActions", action))
                .as((cards, actions) -> {
                    ObjectNode node = NODES.objectNode();
                    node.setAll((ObjectNode) cards);
                    node.setAll((ObjectNode) actions);
                    return (JsonNode) node;
                });
        return bodies(shaped);
    }

    @Provide
    Arbitrary<String> tokenBodies() {
        // RFC 6750 section 2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        Arbitrary<String> b64token = Combinators.combine(
                Arbitraries.strings().alpha().numeric().withChars("-._~+/").ofMinLength(1).ofMaxLength(24),
                Arbitraries.strings().withChars('=').ofMaxLength(2)).as(String::concat);
        return tokenBodies(Arbitraries.oneOf(b64token, Arbitraries.of("", " ", "	")));
    }

    @Provide
    Arbitrary<String> anyTextTokenBodies() {
        return tokenBodies(JsonArbitraries.text());
    }

    private static Arbitrary<String> tokenBodies(Arbitrary<String> textTokens) {
        Arbitrary<JsonNode> accessToken = Arbitraries.frequencyOf(
                Tuple.of(3, textTokens.map(NODES::textNode)),
                Tuple.of(3, JsonArbitraries.value(1)),
                Tuple.of(1, Arbitraries.just((JsonNode) null)));
        Arbitrary<JsonNode> expiresIn = Arbitraries.frequencyOf(
                Tuple.of(3, JsonArbitraries.scalar()),
                Tuple.of(1, JsonArbitraries.value(1)),
                Tuple.of(1, Arbitraries.just((JsonNode) null)));
        Arbitrary<JsonNode> shaped = Combinators.combine(accessToken, expiresIn,
                JsonArbitraries.objectWith(List.of("token_type", "scope", "error", "error_description"), 1))
                .as((token, expires, rest) -> {
                    ObjectNode node = ((ObjectNode) rest).deepCopy();
                    if (token != null) {
                        node.set("access_token", token);
                    }
                    if (expires != null) {
                        node.set("expires_in", expires);
                    }
                    return node;
                });
        return bodies(shaped);
    }

    /** An object holding {@code field}: usually an array of {@code entries}, sometimes any value or absent. */
    private static Arbitrary<JsonNode> wrapper(String field, Arbitrary<JsonNode> entries) {
        Arbitrary<JsonNode> array = entries.injectNull(0.1)
                .map(entry -> entry == null ? NODES.nullNode() : entry)
                .list().ofMaxSize(4).map(JsonArbitraries::array);
        Arbitrary<JsonNode> value = Arbitraries.frequencyOf(
                Tuple.of(6, array),
                Tuple.of(1, JsonArbitraries.value(1)));
        return Arbitraries.frequencyOf(
                Tuple.of(9, value.map(v -> (JsonNode) NODES.objectNode().set(field, v))),
                Tuple.of(1, Arbitraries.just(NODES.objectNode())));
    }

    /** Mostly the shaped JSON; otherwise any JSON value, a truncated document or text that is not JSON. */
    private static Arbitrary<String> bodies(Arbitrary<JsonNode> shaped) {
        Arbitrary<String> json = shaped.map(JsonNode::toString);
        Arbitrary<String> truncated = Combinators.combine(json, Arbitraries.doubles().between(0, 1))
                .as((text, fraction) -> text.substring(0, (int) (text.length() * fraction)));
        return Arbitraries.frequencyOf(
                Tuple.of(12, json),
                Tuple.of(2, JsonArbitraries.value(3).map(JsonNode::toString)),
                Tuple.of(1, truncated),
                Tuple.of(1, JsonArbitraries.text()));
    }
}
