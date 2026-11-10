package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.List;

/** Permissions-Policy: which powerful browser features (camera, geolocation...) the page may use. */
public final class PermissionsPolicyCheck implements Check {

    @Override
    public String name() {
        return "Permissions-Policy";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        return s.headers().has("Permissions-Policy") ? List.of() : List.of(new Finding(
                "permissions.missing", Severity.LOW,
                "Permissions-Policy header is missing",
                "Turn off features you don't use, e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()"));
    }
}
