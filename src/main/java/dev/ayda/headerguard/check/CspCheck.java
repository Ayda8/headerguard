package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Content-Security-Policy: the main browser-side defence against XSS. */
public final class CspCheck implements Check {

    @Override
    public String name() {
        return "Content-Security-Policy";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        Optional<String> header = s.headers().first("Content-Security-Policy");
        if (header.isEmpty() || header.get().isBlank()) {
            String fix = s.headers().has("Content-Security-Policy-Report-Only")
                    ? "You have a Report-Only policy. Once reports are clean, send it as Content-Security-Policy."
                    : "Start with: Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; object-src 'none'";
            return List.of(new Finding("csp.missing", Severity.MEDIUM,
                    "Content-Security-Policy header is missing", fix));
        }
        Map<String, String> directives = parse(header.get());
        List<Finding> findings = new ArrayList<>();

        String scriptSrc = directives.getOrDefault("script-src", directives.get("default-src"));
        if (scriptSrc == null) {
            findings.add(new Finding("csp.no-script-policy", Severity.MEDIUM,
                    "CSP sets neither script-src nor default-src, so scripts are unrestricted",
                    "Add default-src 'self' (or an explicit script-src)."));
            return findings;
        }
        if (scriptSrc.contains("'unsafe-inline'") && !scriptSrc.contains("'nonce-") && !scriptSrc.contains("'sha")) {
            findings.add(new Finding("csp.unsafe-inline", Severity.MEDIUM,
                    "CSP allows 'unsafe-inline' scripts, which defeats most XSS protection",
                    "Move inline scripts to files, or use nonces / hashes instead of 'unsafe-inline'."));
        }
        if (scriptSrc.contains("'unsafe-eval'")) {
            findings.add(new Finding("csp.unsafe-eval", Severity.LOW,
                    "CSP allows 'unsafe-eval'",
                    "Remove 'unsafe-eval'; replace eval()/new Function() in your code or libraries."));
        }
        for (String source : scriptSrc.split("\\s+")) {
            if (source.equals("*") || source.equals("http:") || source.equals("https:")) {
                findings.add(new Finding("csp.wildcard-source", Severity.MEDIUM,
                        "CSP lets scripts load from any host (" + source + ")",
                        "List the specific hosts you load scripts from instead of a wildcard."));
                break;
            }
        }
        return findings;
    }

    /** Splits a policy into directive name to source list. Later duplicates are ignored, as browsers do. */
    static Map<String, String> parse(String policy) {
        Map<String, String> directives = new LinkedHashMap<>();
        for (String raw : policy.split(";")) {
            String d = raw.trim();
            if (d.isEmpty()) {
                continue;
            }
            int space = d.indexOf(' ');
            String name = (space < 0 ? d : d.substring(0, space)).toLowerCase();
            String value = space < 0 ? "" : d.substring(space + 1).trim().toLowerCase();
            directives.putIfAbsent(name, value);
        }
        return directives;
    }
}
