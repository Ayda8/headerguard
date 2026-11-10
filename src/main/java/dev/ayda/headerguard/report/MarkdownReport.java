package dev.ayda.headerguard.report;

import dev.ayda.headerguard.Audit;
import dev.ayda.headerguard.check.Finding;

import java.util.List;
import java.util.Map;

/** Markdown for the GitHub Actions job summary (and for pasting into issues). */
public final class MarkdownReport implements Report {

    @Override
    public String render(Audit audit) {
        StringBuilder md = new StringBuilder();
        md.append("## headerguard: grade ").append(audit.grade())
                .append(" (").append(audit.score()).append("/100)\n\n");
        md.append("Scanned `").append(audit.snapshot().finalUri()).append("`\n\n");
        if (audit.snapshot().status() >= 400) {
            md.append("> [!WARNING]\n> The server answered HTTP ").append(audit.snapshot().status())
                    .append(". Error pages often lack the headers real pages send, so treat this grade with care.\n\n");
        }
        md.append("| Check | Result |\n|---|---|\n");
        for (Map.Entry<String, List<Finding>> e : audit.results().entrySet()) {
            md.append("| ").append(e.getKey()).append(" | ")
                    .append(e.getValue().isEmpty() ? "✅ pass" : "❌ " + e.getValue().size() + " issue(s)")
                    .append(" |\n");
        }
        List<Finding> findings = audit.findings();
        if (!findings.isEmpty()) {
            md.append("\n| Severity | Issue | Fix |\n|---|---|---|\n");
            for (Finding f : findings) {
                md.append("| ").append(f.severity()).append(" | ")
                        .append(escape(f.title())).append(" | ").append(escape(f.fix())).append(" |\n");
            }
        }
        return md.toString();
    }

    private static String escape(String s) {
        return s.replace("|", "\\|");
    }
}
