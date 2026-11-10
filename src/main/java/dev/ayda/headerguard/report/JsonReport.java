package dev.ayda.headerguard.report;

import dev.ayda.headerguard.Audit;
import dev.ayda.headerguard.check.Finding;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Machine-readable output for pipelines and dashboards. Hand-written to keep the tool dependency-free. */
public final class JsonReport implements Report {

    @Override
    public String render(Audit audit) {
        String checks = audit.results().entrySet().stream()
                .map(this::check)
                .collect(Collectors.joining(",\n    "));
        return """
                {
                  "url": %s,
                  "finalUrl": %s,
                  "status": %d,
                  "tlsProtocol": %s,
                  "score": %d,
                  "grade": %s,
                  "checks": [
                    %s
                  ]
                }
                """.formatted(
                str(audit.snapshot().requested().toString()),
                str(audit.snapshot().finalUri().toString()),
                audit.snapshot().status(),
                audit.snapshot().tls() == null ? "null" : str(audit.snapshot().tls().protocol()),
                audit.score(),
                str(audit.grade()),
                checks);
    }

    private String check(Map.Entry<String, List<Finding>> entry) {
        String findings = entry.getValue().stream()
                .map(f -> "{\"id\": %s, \"severity\": %s, \"title\": %s, \"fix\": %s}".formatted(
                        str(f.id()), str(f.severity().name()), str(f.title()), str(f.fix())))
                .collect(Collectors.joining(", "));
        return "{\"name\": %s, \"passed\": %b, \"findings\": [%s]}".formatted(
                str(entry.getKey()), entry.getValue().isEmpty(), findings);
    }

    static String str(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"').toString();
    }
}
