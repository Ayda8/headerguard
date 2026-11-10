package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.List;
import java.util.Optional;

/** Referrer-Policy: how much of the current URL leaks to other sites when a user clicks a link. */
public final class ReferrerPolicyCheck implements Check {

    @Override
    public String name() {
        return "Referrer-Policy";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        Optional<String> header = s.headers().first("Referrer-Policy");
        if (header.isEmpty()) {
            return List.of(new Finding("referrer.missing", Severity.LOW,
                    "Referrer-Policy header is missing",
                    "Add: Referrer-Policy: strict-origin-when-cross-origin"));
        }
        // The header may list fallbacks; browsers use the last one they understand.
        String[] policies = header.get().toLowerCase().split(",");
        String effective = policies[policies.length - 1].trim();
        if (effective.equals("unsafe-url") || effective.equals("no-referrer-when-downgrade")) {
            return List.of(new Finding("referrer.leaky", Severity.MEDIUM,
                    "Referrer-Policy '" + effective + "' sends full URLs (paths, query strings) to other sites",
                    "Use strict-origin-when-cross-origin, or no-referrer for sensitive apps."));
        }
        return List.of();
    }
}
