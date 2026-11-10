package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Information disclosure: headers that advertise exact software versions to attackers. */
public final class DisclosureCheck implements Check {

    private static final Pattern HAS_VERSION = Pattern.compile("\\d+\\.\\d+");
    private static final List<String> TECH_HEADERS = List.of("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version");

    @Override
    public String name() {
        return "Information disclosure";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        List<Finding> findings = new ArrayList<>();
        s.headers().first("Server")
                .filter(v -> HAS_VERSION.matcher(v).find())
                .ifPresent(v -> findings.add(new Finding("disclosure.server-version", Severity.LOW,
                        "Server header reveals the exact version: " + v,
                        "Hide the version (nginx: server_tokens off; Apache: ServerTokens Prod).")));
        for (String header : TECH_HEADERS) {
            s.headers().first(header).ifPresent(v -> findings.add(new Finding(
                    "disclosure." + header.toLowerCase(), Severity.LOW,
                    header + " reveals the tech stack: " + v,
                    "Remove the " + header + " header.")));
        }
        return findings;
    }
}
