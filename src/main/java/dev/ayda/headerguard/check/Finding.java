package dev.ayda.headerguard.check;

import java.util.Objects;

/**
 * One problem found during a scan.
 *
 * @param id       stable machine-readable id, e.g. {@code hsts.missing}
 * @param severity how serious it is
 * @param title    one-line summary
 * @param fix      what to change to make it go away
 */
public record Finding(String id, Severity severity, String title, String fix) {

    public Finding {
        Objects.requireNonNull(id);
        Objects.requireNonNull(severity);
        Objects.requireNonNull(title);
        Objects.requireNonNull(fix);
    }
}
