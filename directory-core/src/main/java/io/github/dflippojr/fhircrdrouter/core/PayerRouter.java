package io.github.dflippojr.fhircrdrouter.core;

import java.util.Objects;

/**
 * Resolves {@code payerId -> ConnectionRecord}. This is the whole "router":
 * v1 routing is by explicit payer ID only (no resolution from member/plan
 * info) — see the capsule's "Open Questions" for a possible v2.
 */
public final class PayerRouter {

    private final ConnectionStore store;

    public PayerRouter(ConnectionStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    /** Resolves the connection for a payer in a given environment. */
    public ConnectionRecord resolve(String payerId, Environment environment) {
        return store.findByPayerIdAndEnvironment(payerId, environment)
                .filter(record -> record.status() != ConnectionStatus.DEPRECATED)
                .orElseThrow(() -> new RouterException(
                        "No active connection for payerId=" + payerId + " environment=" + environment));
    }

    /** Convenience overload defaulting to {@link Environment#PRODUCTION}. */
    public ConnectionRecord resolve(String payerId) {
        return resolve(payerId, Environment.PRODUCTION);
    }
}
