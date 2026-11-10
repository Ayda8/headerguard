package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.List;

/** A single security rule. Implementations must be pure: no network, no clock, no state. */
public interface Check {

    /** Short name shown in reports, e.g. "HSTS". */
    String name();

    /** Returns the problems found, or an empty list if the site passes. */
    List<Finding> inspect(Snapshot snapshot);

    /** All built-in checks, in report order. */
    static List<Check> defaults() {
        return List.of(
                new TransportCheck(),
                new HstsCheck(),
                new CspCheck(),
                new FramingCheck(),
                new ContentTypeOptionsCheck(),
                new ReferrerPolicyCheck(),
                new PermissionsPolicyCheck(),
                new CookieCheck(),
                new CorsCheck(),
                new DisclosureCheck());
    }
}
