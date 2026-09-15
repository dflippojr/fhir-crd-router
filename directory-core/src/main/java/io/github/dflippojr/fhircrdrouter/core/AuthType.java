package io.github.dflippojr.fhircrdrouter.core;

/** How a payer's CDS Hooks endpoint expects to be authenticated. */
public enum AuthType {
    OAUTH2_CLIENT_CREDENTIALS,
    API_KEY,
    MUTUAL_TLS,
    NONE
}
