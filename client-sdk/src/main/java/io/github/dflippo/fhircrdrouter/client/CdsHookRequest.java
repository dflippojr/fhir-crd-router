package io.github.dflippo.fhircrdrouter.client;

import java.util.Map;

/**
 * A CDS Hooks invocation request. {@code context} and {@code prefetch} are
 * left as generic maps since their shape is entirely hook-specific.
 */
public record CdsHookRequest(
        String hook,
        String hookInstance,
        Map<String, Object> context,
        Map<String, Object> prefetch
) {
}
