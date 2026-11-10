package dev.ayda.headerguard.report;

import dev.ayda.headerguard.Audit;
import dev.ayda.headerguard.check.Finding;
import dev.ayda.headerguard.check.Severity;

import java.util.List;
import java.util.Map;

/** Terminal output, optionally with ANSI colours. */
public final class TextReport implements Report {

    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String DIM = "\u001B[2m";
    private static final String GREEN = "\u001B[32m";

    private final boolean color;
    private final String pass;
    private final String fail;
    private final String dot;

    /**
     * @param color   use ANSI colours
     * @param unicode use ✓ ✗ · symbols; turn off for consoles that are not UTF-8 (e.g. default Windows cmd)
     */
    public TextReport(boolean color, boolean unicode) {
        this.color = color;
        this.pass = unicode ? "✓" : "+";
        this.fail = unicode ? "✗" : "x";
        this.dot = unicode ? "·" : "-";
    }

    @Override
    public String render(Audit audit) {
        StringBuilder out = new StringBuilder();
        out.append(paint(BOLD, "headerguard")).append(' ').append(dot).append(' ').append(audit.snapshot().finalUri()).append('\n');
        out.append("HTTP ").append(audit.snapshot().status());
        if (audit.snapshot().tls() != null) {
            out.append(' ').append(dot).append(' ').append(audit.snapshot().tls().protocol());
        }
        out.append('\n');
        if (audit.snapshot().status() >= 400) {
            out.append(paint("\u001B[33m", "Note: the server answered HTTP " + audit.snapshot().status()
                    + ". Error pages (or a proxy in between) often lack the headers your real pages send,"
                    + " so treat this grade with care.")).append('\n');
        }
        out.append('\n');

        for (Map.Entry<String, List<Finding>> entry : audit.results().entrySet()) {
            if (entry.getValue().isEmpty()) {
                out.append(paint(GREEN, "  " + pass + " ")).append(entry.getKey()).append('\n');
                continue;
            }
            out.append(paint(colorOf(entry.getValue().get(0).severity()), "  " + fail + " "))
                    .append(entry.getKey()).append('\n');
            for (Finding f : entry.getValue()) {
                out.append("      ").append(paint(colorOf(f.severity()), String.format("%-8s", f.severity())))
                        .append(' ').append(f.title()).append('\n');
                out.append("      ").append(paint(DIM, "         fix: " + f.fix())).append('\n');
            }
        }

        out.append('\n').append(paint(BOLD, "Grade " + audit.grade() + "  " + dot + "  score " + audit.score() + "/100"));
        out.append(paint(DIM, String.format("   (%d critical, %d high, %d medium, %d low)",
                audit.count(Severity.CRITICAL), audit.count(Severity.HIGH),
                audit.count(Severity.MEDIUM), audit.count(Severity.LOW)))).append('\n');
        return out.toString();
    }

    private String colorOf(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "\u001B[1;31m";
            case HIGH -> "\u001B[31m";
            case MEDIUM -> "\u001B[33m";
            case LOW -> "\u001B[36m";
            case INFO -> DIM;
        };
    }

    private String paint(String ansi, String text) {
        return color ? ansi + text + RESET : text;
    }
}
