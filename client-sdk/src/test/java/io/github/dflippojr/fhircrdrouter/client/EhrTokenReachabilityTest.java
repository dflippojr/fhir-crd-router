package io.github.dflippojr.fhircrdrouter.client;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest.FhirAuthorization;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * No exception that leaves a token-bearing hook call, and no listener exchange of that call, can reach
 * the EHR's {@code fhirAuthorization} token through any object it references: causes, suppressed
 * exceptions, Jackson path references and their {@code from} objects, processors, or any other field
 * reachable by reflection (#164). An exception leaving the call has no cause and no suppressed
 * exceptions at all.
 */
class EhrTokenReachabilityTest {
    private static final String TOKEN = "ReachEhrToken164abcdef";
    private static final String EHR = "https://ehr.example.org/fhir";
    private final List<PayerExchange> exchanges = new CopyOnWriteArrayList<>();
    private final List<AutoCloseable> closers = new ArrayList<>();

    @AfterEach
    void stop() throws Exception {
        for (AutoCloseable closer : closers) {
            closer.close();
        }
    }

    @Test
    void serializationFailureWithAnOrdinaryKey() {
        CdsHookRequest request = request(Map.of("patientId", "pat-1", "bad", new Object()));

        RuntimeException e = assertThrows(RuntimeException.class,
                () -> client().callHook(record("http://127.0.0.1:9", AuthType.NONE, null), "x", request));

        assertLeavesNothing(e);
        assertTrue(exchanges.isEmpty());
    }

    @Test
    void hookTransportFailure() throws Exception {
        int port = rawServer(List.of("HTTP/1.1 2x0 broken\r\n\r\n"));

        PayerCallException e = assertThrows(PayerCallException.class,
                () -> client().callHook(record("http://127.0.0.1:" + port, AuthType.NONE, null), "x",
                        request(Map.of("patientId", "pat-1"))));

        assertLeavesNothing(e);
        assertFalse(e.timedOut());
        assertTrue(e.statusCode().isEmpty());
        assertFalse(exchanges.isEmpty());
    }

    @Test
    void oauthRefreshTransportFailureAfterA401() throws Exception {
        String token = "{\"access_token\":\"payer-1\",\"token_type\":\"Bearer\",\"expires_in\":300}";
        int tokenPort = rawServer(List.of(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                        + token.length() + "\r\n\r\n" + token,
                "HTTP/1.1 2x0 broken\r\n\r\n"));
        HttpServer hooks = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger calls = new AtomicInteger();
        hooks.createContext("/cds-services/x", e -> {
            e.getRequestBody().readAllBytes();
            TestResponses.respond(e, calls.incrementAndGet() == 1 ? 401 : 200, "{\"cards\":[]}");
        });
        hooks.start();
        closers.add(() -> hooks.stop(0));
        String base = "http://127.0.0.1:" + hooks.getAddress().getPort();

        PayerCallException e = assertThrows(PayerCallException.class,
                () -> client().callHook(record(base, AuthType.OAUTH2_CLIENT_CREDENTIALS,
                        "http://127.0.0.1:" + tokenPort + "/token"), "x", request(Map.of("patientId", "pat-1"))));

        assertLeavesNothing(e);
        assertEquals(PayerCallPhase.TOKEN, e.phase());
        assertEquals(List.of(PayerCallPhase.TOKEN, PayerCallPhase.HOOK, PayerCallPhase.TOKEN),
                exchanges.stream().map(PayerExchange::phase).toList());
    }

    @Test
    void theWalkerFindsTheTokenThroughAJacksonPathReference() {
        CdsHookRequest request = request(Map.of("bad", new Object()));
        com.fasterxml.jackson.databind.JsonMappingException e = assertThrows(
                com.fasterxml.jackson.databind.JsonMappingException.class,
                () -> new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(request));
        assertFalse(e.getMessage().contains(TOKEN), "the text is clean");
        assertSame(request, e.getPath().get(0).getFrom(), "the path still references the request");

        assertThrows(org.opentest4j.AssertionFailedError.class, () -> assertUnreachable(e));
    }

    /** No cause, no suppressed, and the token unreachable from the exception or any exchange. */
    private void assertLeavesNothing(Throwable e) {
        assertNull(e.getCause(), () -> "cause attached: " + e.getCause());
        assertEquals(0, e.getSuppressed().length, "suppressed attached");
        assertUnreachable(e);
        exchanges.forEach(EhrTokenReachabilityTest::assertUnreachable);
    }

    /** Walks every object reachable from {@code root} and fails if any string in it holds the token. */
    static void assertUnreachable(Object root) {
        Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<Object> todo = new ArrayDeque<>(List.of(root));
        while (!todo.isEmpty()) {
            Object o = todo.pop();
            if (o == null || !seen.add(o)) {
                continue;
            }
            if (o instanceof CharSequence text) {
                assertFalse(text.toString().contains(TOKEN), () -> "token reachable from " + root.getClass().getName());
                continue;
            }
            if (o instanceof Throwable t) {
                todo.push(String.valueOf(t.getMessage()));
                todo.push(String.valueOf(t.getLocalizedMessage()));
                todo.push(t.toString());
                for (StackTraceElement frame : t.getStackTrace()) {
                    todo.push(frame.toString());
                }
                if (t.getCause() != null) {
                    todo.push(t.getCause());
                }
                Collections.addAll(todo, (Object[]) t.getSuppressed());
            }
            if (o instanceof Collection<?> c) {
                todo.addAll(c);
                continue;
            }
            if (o instanceof Map<?, ?> m) {
                todo.addAll(m.keySet());
                todo.addAll(m.values());
                continue;
            }
            if (o instanceof Optional<?> opt) {
                opt.ifPresent(todo::push);
                continue;
            }
            if (o.getClass().isArray()) {
                if (!o.getClass().getComponentType().isPrimitive()) {
                    for (int i = 0; i < Array.getLength(o); i++) {
                        todo.push(Array.get(o, i));
                    }
                }
                continue;
            }
            if (o instanceof HttpHeaders headers) {
                todo.push(headers.map());
                continue;
            }
            if (o instanceof URI uri) {
                todo.push(uri.toString());
                todo.push(String.valueOf(uri.getPath()) + uri.getQuery() + uri.getAuthority());
                continue;
            }
            Class<?> type = o.getClass();
            if (type.getName().startsWith("java.") || type.getName().startsWith("javax.")
                    || type.getName().startsWith("jdk.") || type.getName().startsWith("sun.")) {
                // JDK internals are closed to reflection; their string form is the best available view.
                if (!(o instanceof Throwable)) {
                    todo.push(String.valueOf(o));
                }
                continue;
            }
            for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
                if (c.getName().startsWith("java.")) {
                    break;
                }
                for (Field field : c.getDeclaredFields()) {
                    if (Modifier.isStatic(field.getModifiers()) || field.getType().isPrimitive()) {
                        continue;
                    }
                    try {
                        field.setAccessible(true);
                        todo.push(field.get(o));
                    } catch (ReflectiveOperationException | RuntimeException inaccessible) {
                        todo.push(String.valueOf(o));
                    }
                }
            }
        }
    }

    /** A loopback server that answers each connection, in order, with the next raw response. */
    private int rawServer(List<String> responses) throws IOException {
        ServerSocket socket = new ServerSocket(0, 4, InetAddress.getLoopbackAddress());
        closers.add(socket);
        Thread server = new Thread(() -> {
            for (String response : responses) {
                try (Socket client = socket.accept()) {
                    InputStream in = client.getInputStream();
                    byte[] buffer = new byte[16384];
                    in.read(buffer);
                    OutputStream out = client.getOutputStream();
                    out.write(response.getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                } catch (IOException closed) {
                    return;
                }
            }
        });
        server.setDaemon(true);
        server.start();
        return socket.getLocalPort();
    }

    private static CdsHookRequest request(Map<String, Object> context) {
        return new CdsHookRequest("order-sign", "instance", context, Map.of())
                .withFhirServer(EHR, new FhirAuthorization(TOKEN, "Bearer", 300, "patient/Patient.read", "payer-client"));
    }

    private static ConnectionRecord record(String base, AuthType auth, String tokenEndpoint) {
        ConnectionRecord.Builder builder = ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                .baseUrl(base).authType(auth);
        return tokenEndpoint == null ? builder.build()
                : builder.credentialRef("credential").clientId("client").tokenEndpoint(tokenEndpoint).build();
    }

    private CdsHooksClient client() {
        CredentialProvider credentials = new CredentialProvider() {
            public Optional<String> resolve(String ref) { return Optional.of("client-secret"); }
            public void put(String ref, String value) { throw new UnsupportedOperationException(); }
            public void remove(String ref) { throw new UnsupportedOperationException(); }
        };
        return new CdsHooksClient(HttpClient.newHttpClient(), credentials, null, Duration.ofSeconds(5),
                Duration.ofSeconds(1), exchanges::add);
    }
}
