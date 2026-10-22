package io.github.dflippojr.fhircrdrouter.core;

/**
 * Lifecycle status of a {@link ConnectionRecord}. Only {@link #ACTIVE} is routable by
 * {@link PayerRouter#resolve}; {@code CdsHooksClient.verify} runs on any status.
 */
public enum ConnectionStatus {
    /** In use: {@link PayerRouter#resolve} returns it. */
    ACTIVE,
    /** Switched off for now: {@link PayerRouter#resolve} refuses it. */
    INACTIVE,
    /** Retired: {@link PayerRouter#resolve} refuses it. */
    DEPRECATED
}
