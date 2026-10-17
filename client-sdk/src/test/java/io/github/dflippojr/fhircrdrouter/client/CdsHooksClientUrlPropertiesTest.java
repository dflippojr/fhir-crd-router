package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.testsupport.JsonArbitraries;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Received;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * For any service id and hook name, a hook call goes to exactly one encoded path segment under
 * {@code <base path>/cds-services/} and adds no query (the #71 class). Checked on the wire.
 */
class CdsHooksClientUrlPropertiesTest {

    /** Fixed so CI is reproducible; jqwik prints the seed and the shrunk sample on failure. */
    private static final String SEED = "98071";
    private static final Pattern ENCODED_SEGMENT = Pattern.compile("([A-Za-z0-9\\-._~]|%[0-9A-F]{2})+");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final CredentialProvider NO_CREDENTIALS = new CredentialProvider() {
        @Override public Optional<String> resolve(String credentialRef) { return Optional.empty(); }
        @Override public void put(String credentialRef, String secretValue) { }
        @Override public void remove(String credentialRef) { }
    };

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
    void hookCallStaysOneSegmentUnderTheBasePath(@ForAll("serviceIds") String serviceId,
                                                 @ForAll("text") String hook,
                                                 @ForAll("basePaths") String basePath,
                                                 @ForAll boolean trailingSlash) throws Exception {
        payer.reset(request -> new Reply(200, "{\"cards\":[]}"));
        ConnectionRecord record = ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl(payer.origin() + basePath + (trailingSlash ? "/" : "")).authType(AuthType.NONE).build();
        CdsHookRequest request = new CdsHookRequest(hook, "instance", Map.of(), null);
        CdsHooksClient client = new CdsHooksClient(HTTP, NO_CREDENTIALS);

        if (serviceId.isEmpty() || serviceId.equals(".") || serviceId.equals("..")) {
            assertThrows(IllegalArgumentException.class, () -> client.callHook(record, serviceId, request));
            assertTrue(payer.received().isEmpty());
            return;
        }
        client.callHook(record, serviceId, request);

        List<Received> received = payer.received();
        assertEquals(1, received.size());
        Received sent = received.get(0);
        String prefix = basePath + "/cds-services/";
        assertTrue(sent.rawPath().startsWith(prefix), sent.rawPath());
        String segment = sent.rawPath().substring(prefix.length());
        assertTrue(ENCODED_SEGMENT.matcher(segment).matches(), segment);
        assertTrue(!segment.equals(".") && !segment.equals(".."), segment);
        assertEquals(sent.rawPath(), URI.create(sent.rawPath()).normalize().getRawPath());
        assertNull(sent.rawQuery());
        assertEquals(serviceId, URLDecoder.decode(segment, StandardCharsets.UTF_8));
        assertEquals("POST", sent.method());
        assertEquals(hook, MAPPER.readTree(sent.body()).get("hook").textValue());
    }

    @Provide
    Arbitrary<String> serviceIds() {
        return Arbitraries.oneOf(JsonArbitraries.text(),
                Arbitraries.strings().withChars("./%?#").ofMinLength(1).ofMaxLength(4));
    }

    @Provide
    Arbitrary<String> text() {
        return JsonArbitraries.text();
    }

    /** A configured base path such as {@code /fhir/r4}; empty for a payer at the origin root. */
    @Provide
    Arbitrary<String> basePaths() {
        return Arbitraries.strings().alpha().numeric().withChars("-_").ofMinLength(1).ofMaxLength(8)
                .list().ofMaxSize(3).map(segments -> segments.stream().map(s -> "/" + s).collect(Collectors.joining()));
    }
}
