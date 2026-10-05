package io.github.dflippojr.fhircrdrouter.client;

/** Receives redacted exchanges synchronously, in send order. Implementations must be thread safe when sharing a client. */
@FunctionalInterface
public interface PayerExchangeListener {
    PayerExchangeListener NOOP = exchange -> { };

    /** Listener exceptions are ignored so diagnostics cannot change the payer call's result. */
    void onExchange(PayerExchange exchange);
}
