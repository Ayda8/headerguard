package dev.ayda.headerguard;

import dev.ayda.headerguard.check.Check;
import dev.ayda.headerguard.check.Finding;
import dev.ayda.headerguard.check.Severity;
import dev.ayda.headerguard.scan.Snapshot;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The result of running every check against one snapshot.
 *
 * @param snapshot what was scanned
 * @param results  findings per check name, in check order (empty list = passed)
 */
public record Audit(Snapshot snapshot, Map<String, List<Finding>> results) {

    public static Audit run(Snapshot snapshot, List<Check> checks) {
        Map<String, List<Finding>> results = new LinkedHashMap<>();
        for (Check check : checks) {
            List<Finding> findings = check.inspect(snapshot).stream()
                    .sorted(Comparator.comparing(Finding::severity))
                    .toList();
            results.put(check.name(), findings);
        }
        return new Audit(snapshot, results);
    }

    public List<Finding> findings() {
        return results.values().stream().flatMap(List::stream)
                .sorted(Comparator.comparing(Finding::severity))
                .toList();
    }

    /** 100 minus the penalty of every finding, never below 0. */
    public int score() {
        int penalty = findings().stream().mapToInt(f -> f.severity().penalty()).sum();
        return Math.max(0, 100 - penalty);
    }

    /** Letter grade. Any CRITICAL finding caps the grade at F, however good the rest is. */
    public String grade() {
        if (findings().stream().anyMatch(f -> f.severity() == Severity.CRITICAL)) {
            return "F";
        }
        int s = score();
        if (s >= 90) return "A";
        if (s >= 80) return "B";
        if (s >= 70) return "C";
        if (s >= 60) return "D";
        return "F";
    }

    public long count(Severity severity) {
        return findings().stream().filter(f -> f.severity() == severity).count();
    }
}
