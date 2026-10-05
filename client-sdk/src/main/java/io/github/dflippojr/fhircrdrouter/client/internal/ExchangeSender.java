package io.github.dflippojr.fhircrdrouter.client.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PayerExchange;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.TreeMap;

/** Shared SDK implementation detail for payer and OAuth2 HTTP attempts. */
public final class ExchangeSender {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ExchangeSender() { }

    public static HttpResponse<String> send(HttpClient client, HttpRequest request, String body,
                                            ConnectionRecord record, PayerCallPhase phase, int attempt,
                                            PayerExchangeListener listener) throws IOException, InterruptedException {
        Instant startedAt = Instant.now();
        long start = System.nanoTime();
        HttpResponse<String> response = null;
        Exception error = null;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response;
        } catch (IOException | InterruptedException e) {
            error = e;
            throw e;
        } finally {
            Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
            if (listener != PayerExchangeListener.NOOP) {
                report(listener, new PayerExchange(phase, record.payerId(), record.environment(),
                        request.method(), request.uri(), attempt, startedAt, elapsed,
                        response == null ? OptionalInt.empty() : OptionalInt.of(response.statusCode()),
                        safeHeaders(request.headers(), true),
                        response == null ? HttpHeaders.of(Map.of(), (k, v) -> true) : safeHeaders(response.headers(), false),
                        phase == PayerCallPhase.TOKEN ? null : body,
                        response == null ? null : safeBody(phase, response.body()), error));
            }
        }
    }

    private static void report(PayerExchangeListener listener, PayerExchange exchange) {
        try {
            listener.onExchange(exchange);
        } catch (Exception ignored) {
            // Observability must never change the call's result, including transport failures.
        }
    }

    private static HttpHeaders safeHeaders(HttpHeaders headers, boolean request) {
        Map<String, List<String>> safe = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.map().forEach((name, values) -> {
            if (request && name.equalsIgnoreCase("Authorization")) {
                safe.put(name, values.stream().map(ExchangeSender::redactAuthorization).toList());
            } else if (!name.equalsIgnoreCase("Set-Cookie")) {
                safe.put(name, values);
            }
        });
        return HttpHeaders.of(safe, (k, v) -> true);
    }

    private static String redactAuthorization(String value) {
        int space = value.indexOf(' ');
        return space > 0 ? value.substring(0, space) + " [REDACTED]" : "[REDACTED]";
    }

    private static String safeBody(PayerCallPhase phase, String body) {
        if (phase != PayerCallPhase.TOKEN) {
            return body;
        }
        var safe = MAPPER.createObjectNode();
        try {
            JsonNode json = MAPPER.readTree(body);
            for (String field : List.of("token_type", "expires_in", "scope")) {
                if (json != null && json.has(field) && json.get(field).isValueNode()) {
                    safe.set(field, json.get(field));
                }
            }
        } catch (IOException ignored) {
            // Never expose raw token responses or parser exceptions containing their source.
        }
        return safe.toString();
    }
}
