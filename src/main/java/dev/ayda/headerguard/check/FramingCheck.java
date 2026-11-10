package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.List;

/** Clickjacking: can another site load this page in an invisible frame? */
public final class FramingCheck implements Check {

    @Override
    public String name() {
        return "Clickjacking protection";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        boolean frameAncestors = s.headers().first("Content-Security-Policy")
                .map(CspCheck::parse)
                .map(d -> d.containsKey("frame-ancestors"))
                .orElse(false);
        String xfo = s.headers().first("X-Frame-Options").orElse("").toUpperCase();
        boolean xfoOk = xfo.equals("DENY") || xfo.equals("SAMEORIGIN");
        if (frameAncestors || xfoOk) {
            return List.of();
        }
        return List.of(new Finding("framing.unprotected", Severity.MEDIUM,
                "Page can be framed by any site (clickjacking)",
                "Add CSP frame-ancestors 'self' (modern) or X-Frame-Options: DENY (legacy browsers)."));
    }
}
