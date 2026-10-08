package io.github.dflippojr.fhircrdrouter.client;

import java.util.Objects;
import java.util.function.Consumer;

/** Receives redacted exchanges synchronously, in send order. Implementations must be thread safe when sharing a client. */
@FunctionalInterface
public interface PayerExchangeListener {
    PayerExchangeListener NOOP = exchange -> { };

    /** Listener exceptions are ignored so diagnostics cannot change the payer call's result. */
    void onExchange(PayerExchange exchange);

    /**
     * Adapts a consumer of {@link PayerExchangeMetadata} so it never sees raw payloads, headers,
     * URIs or errors. Consumer exceptions are ignored like any other listener's.
     */
    static PayerExchangeListener metadataOnly(Consumer<PayerExchangeMetadata> consumer) {
        Objects.requireNonNull(consumer, "consumer");
        return exchange -> consumer.accept(PayerExchangeMetadata.from(exchange));
    }
}
