package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.List;

/** X-Content-Type-Options: stops browsers from guessing (sniffing) a different content type. */
public final class ContentTypeOptionsCheck implements Check {

    @Override
    public String name() {
        return "X-Content-Type-Options";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        boolean ok = s.headers().first("X-Content-Type-Options")
                .map(v -> v.equalsIgnoreCase("nosniff"))
                .orElse(false);
        return ok ? List.of() : List.of(new Finding("xcto.missing", Severity.LOW,
                "X-Content-Type-Options: nosniff is missing",
                "Add: X-Content-Type-Options: nosniff"));
    }
}
