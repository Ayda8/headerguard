package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Set-Cookie flags: Secure, HttpOnly and SameSite on every cookie the site sets. */
public final class CookieCheck implements Check {

    @Override
    public String name() {
        return "Cookies";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        List<Finding> findings = new ArrayList<>();
        for (String cookie : s.headers().all("Set-Cookie")) {
            String name = cookieName(cookie);
            List<String> attributes = attributes(cookie);
            boolean secure = attributes.contains("secure");
            String sameSite = attributes.stream()
                    .filter(a -> a.startsWith("samesite="))
                    .map(a -> a.substring("samesite=".length()))
                    .findFirst().orElse(null);

            if (s.isHttps() && !secure) {
                findings.add(new Finding("cookie.no-secure", Severity.MEDIUM,
                        "Cookie '" + name + "' is missing Secure, so it can leak over plain HTTP",
                        "Add the Secure attribute to " + name + "."));
            }
            if (!attributes.contains("httponly")) {
                findings.add(new Finding("cookie.no-httponly", Severity.LOW,
                        "Cookie '" + name + "' is readable by JavaScript (no HttpOnly)",
                        "Add HttpOnly to " + name + " unless your frontend really needs to read it."));
            }
            if (sameSite == null) {
                findings.add(new Finding("cookie.no-samesite", Severity.LOW,
                        "Cookie '" + name + "' has no SameSite attribute",
                        "Add SameSite=Lax (or Strict) to " + name + " to limit cross-site requests."));
            } else if (sameSite.equals("none") && !secure) {
                findings.add(new Finding("cookie.samesite-none-insecure", Severity.MEDIUM,
                        "Cookie '" + name + "' uses SameSite=None without Secure; browsers will reject it",
                        "SameSite=None always needs Secure."));
            }
        }
        return findings;
    }

    static String cookieName(String setCookie) {
        int eq = setCookie.indexOf('=');
        return (eq < 0 ? setCookie : setCookie.substring(0, eq)).trim();
    }

    /** Lower-cased attributes after the name=value pair, with whitespace around '=' removed. */
    static List<String> attributes(String setCookie) {
        String[] parts = setCookie.split(";");
        List<String> attrs = new ArrayList<>();
        for (int i = 1; i < parts.length; i++) {
            attrs.add(parts[i].trim().toLowerCase(Locale.ROOT).replaceAll("\\s*=\\s*", "="));
        }
        return attrs;
    }
}
