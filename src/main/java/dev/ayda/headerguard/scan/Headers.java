package dev.ayda.headerguard.scan;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/** Case-insensitive, read-only view of HTTP response headers. */
public final class Headers {

    private final Map<String, List<String>> values;

    private Headers(Map<String, List<String>> values) {
        this.values = values;
    }

    public static Headers of(Map<String, List<String>> raw) {
        Map<String, List<String>> copy = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        raw.forEach((name, list) -> {
            if (name != null) {
                copy.merge(name, List.copyOf(list), (a, b) -> {
                    var merged = new java.util.ArrayList<>(a);
                    merged.addAll(b);
                    return List.copyOf(merged);
                });
            }
        });
        return new Headers(copy);
    }

    /** Convenience for tests: {@code Headers.of("Name", "value", "Other", "value")}. */
    public static Headers of(String... nameValuePairs) {
        if (nameValuePairs.length % 2 != 0) {
            throw new IllegalArgumentException("Expected name/value pairs");
        }
        Map<String, List<String>> raw = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (int i = 0; i < nameValuePairs.length; i += 2) {
            raw.computeIfAbsent(nameValuePairs[i], k -> new java.util.ArrayList<>()).add(nameValuePairs[i + 1]);
        }
        return of(raw);
    }

    public static Headers empty() {
        return of(Map.of());
    }

    public Optional<String> first(String name) {
        List<String> list = values.get(name);
        return list == null || list.isEmpty() ? Optional.empty() : Optional.of(list.get(0).trim());
    }

    public List<String> all(String name) {
        return values.getOrDefault(name, List.of());
    }

    public boolean has(String name) {
        return first(name).filter(v -> !v.isBlank()).isPresent();
    }
}
