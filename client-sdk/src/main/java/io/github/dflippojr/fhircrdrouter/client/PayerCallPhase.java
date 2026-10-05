package io.github.dflippojr.fhircrdrouter.client;

/** The payer endpoint involved in a call. Shared by diagnostics and call errors. */
public enum PayerCallPhase {
    DISCOVERY, TOKEN, HOOK
}
