package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.List;

/**
 * CORS: the scanner sends a request with a made-up foreign Origin and looks at what comes back.
 * Reflecting any origin together with credentials lets any website read a logged-in user's data.
 */
public final class CorsCheck implements Check {

    @Override
    public String name() {
        return "CORS";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        String allowOrigin = s.corsProbe().first("Access-Control-Allow-Origin").orElse(null);
        if (allowOrigin == null) {
            return List.of();
        }
        boolean credentials = s.corsProbe().first("Access-Control-Allow-Credentials")
                .map(v -> v.equalsIgnoreCase("true"))
                .orElse(false);
        boolean reflected = allowOrigin.equalsIgnoreCase(Snapshot.PROBE_ORIGIN);

        if (reflected && credentials) {
            return List.of(new Finding("cors.reflected-with-credentials", Severity.CRITICAL,
                    "CORS trusts any origin AND allows credentials: any website can read users' data",
                    "Check Origin against an explicit allow-list; never echo it back unconditionally."));
        }
        if (allowOrigin.equals("null") && credentials) {
            return List.of(new Finding("cors.null-with-credentials", Severity.HIGH,
                    "CORS trusts the 'null' origin with credentials (reachable from sandboxed iframes)",
                    "Remove 'null' from the allowed origins."));
        }
        if (reflected) {
            return List.of(new Finding("cors.reflected", Severity.MEDIUM,
                    "CORS echoes back any origin",
                    "Use an explicit allow-list of origins. If the API is truly public, use '*' on purpose."));
        }
        if (allowOrigin.equals("*") && credentials) {
            return List.of(new Finding("cors.wildcard-with-credentials", Severity.LOW,
                    "CORS sends '*' with Allow-Credentials: true (browsers reject this; it signals confusion)",
                    "Pick one: a public API with '*' and no credentials, or an allow-list with credentials."));
        }
        return List.of();
    }
}
