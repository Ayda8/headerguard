package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

/** Strict-Transport-Security: tells browsers to never use plain HTTP for this site again. */
public final class HstsCheck implements Check {

    /** 180 days, the minimum most scanners (and the HSTS preload list guidance) consider meaningful. */
    static final long MIN_MAX_AGE = 15_552_000L;

    @Override
    public String name() {
        return "Strict-Transport-Security";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        if (!s.isHttps()) {
            return List.of(); // browsers ignore HSTS over HTTP; TransportCheck already reports this
        }
        Optional<String> header = s.headers().first("Strict-Transport-Security");
        if (header.isEmpty()) {
            return List.of(new Finding("hsts.missing", Severity.HIGH,
                    "Strict-Transport-Security header is missing",
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"));
        }
        List<Finding> findings = new ArrayList<>();
        String value = header.get().toLowerCase();
        OptionalLong maxAge = maxAge(value);
        if (maxAge.isEmpty()) {
            findings.add(new Finding("hsts.invalid", Severity.HIGH,
                    "Strict-Transport-Security has no valid max-age",
                    "Set a numeric max-age, e.g. max-age=31536000 (one year)."));
        } else if (maxAge.getAsLong() < MIN_MAX_AGE) {
            findings.add(new Finding("hsts.short-max-age", Severity.MEDIUM,
                    "HSTS max-age is only " + maxAge.getAsLong() + " seconds",
                    "Raise max-age to at least 15552000 (180 days); one year is common."));
        }
        if (!value.contains("includesubdomains")) {
            findings.add(new Finding("hsts.no-subdomains", Severity.LOW,
                    "HSTS does not cover subdomains",
                    "Add includeSubDomains once every subdomain serves HTTPS."));
        }
        return findings;
    }

    static OptionalLong maxAge(String value) {
        for (String part : value.split(";")) {
            String p = part.trim();
            if (p.startsWith("max-age=")) {
                String n = p.substring("max-age=".length()).replace("\"", "").trim();
                try {
                    return OptionalLong.of(Long.parseLong(n));
                } catch (NumberFormatException e) {
                    return OptionalLong.empty();
                }
            }
        }
        return OptionalLong.empty();
    }
}
