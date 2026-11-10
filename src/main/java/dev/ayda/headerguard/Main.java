package dev.ayda.headerguard;

import dev.ayda.headerguard.check.Check;
import dev.ayda.headerguard.report.JsonReport;
import dev.ayda.headerguard.report.MarkdownReport;
import dev.ayda.headerguard.report.Report;
import dev.ayda.headerguard.report.TextReport;
import dev.ayda.headerguard.scan.Scanner;
import dev.ayda.headerguard.scan.Snapshot;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.function.Function;

/**
 * Command line entry point.
 *
 * <pre>
 * headerguard &lt;url&gt; [--format text|json|markdown] [--fail-under SCORE] [--no-color]
 * </pre>
 *
 * Exit codes: 0 = ok, 1 = score below --fail-under, 2 = usage or network error.
 */
public final class Main {

    static final int OK = 0;
    static final int BELOW_THRESHOLD = 1;
    static final int ERROR = 2;

    private static final String USAGE = """
            Usage: headerguard <url> [options]

              --format text|json|markdown   output format (default: text)
              --fail-under SCORE            exit 1 if the score is below SCORE (0-100); handy in CI
              --no-color                    plain text output (also honoured: NO_COLOR env var)
                                            (set HEADERGUARD_ASCII=1 to force ASCII symbols)
              -h, --help                    show this help

            Only scan sites you own or have permission to test.
            """;

    public static void main(String[] args) throws InterruptedException {
        System.exit(run(args, System.out, System.err, System.getenv(), uri -> {
            try {
                return new Scanner().scan(uri);
            } catch (IOException e) {
                throw new ScanFailed(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ScanFailed(e);
            }
        }));
    }

    static int run(String[] args, PrintStream out, PrintStream err, Map<String, String> env,
                   Function<URI, Snapshot> scanner) {
        String url = null;
        String format = "text";
        Integer failUnder = null;
        boolean color = !env.containsKey("NO_COLOR");

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-h", "--help" -> {
                    out.print(USAGE);
                    return OK;
                }
                case "--no-color" -> color = false;
                case "--format" -> {
                    if (++i >= args.length) return usage(err, "--format needs a value");
                    format = args[i];
                }
                case "--fail-under" -> {
                    if (++i >= args.length) return usage(err, "--fail-under needs a value");
                    try {
                        failUnder = Integer.parseInt(args[i]);
                    } catch (NumberFormatException e) {
                        return usage(err, "--fail-under must be a number, got: " + args[i]);
                    }
                    if (failUnder < 0 || failUnder > 100) return usage(err, "--fail-under must be 0-100");
                }
                default -> {
                    if (a.startsWith("-")) return usage(err, "Unknown option: " + a);
                    if (url != null) return usage(err, "Only one URL at a time");
                    url = a;
                }
            }
        }
        if (url == null) {
            return usage(err, "Missing URL");
        }

        URI target;
        try {
            target = normalize(url);
        } catch (IllegalArgumentException e) {
            return usage(err, "Not a valid URL: " + url);
        }

        Report report = switch (format) {
            case "text" -> new TextReport(color, unicodeConsole(env));
            case "json" -> new JsonReport();
            case "markdown", "md" -> new MarkdownReport();
            default -> null;
        };
        if (report == null) {
            return usage(err, "Unknown format: " + format);
        }

        Audit audit;
        try {
            audit = Audit.run(scanner.apply(target), Check.defaults());
        } catch (ScanFailed e) {
            err.println("Could not reach " + target + ": " + e.getCause());
            return ERROR;
        }

        out.print(report.render(audit));
        writeGithubSummary(audit, env, err);

        if (failUnder != null && audit.score() < failUnder) {
            err.printf("Score %d is below --fail-under %d%n", audit.score(), failUnder);
            return BELOW_THRESHOLD;
        }
        return OK;
    }

    /** True when stdout can print ✓ and ✗. Java reports the console's real encoding in stdout.encoding. */
    static boolean unicodeConsole(Map<String, String> env) {
        if (env.containsKey("HEADERGUARD_ASCII")) {
            return false;
        }
        String enc = System.getProperty("stdout.encoding", System.getProperty("native.encoding", "UTF-8"));
        return enc.toUpperCase().replace("-", "").contains("UTF8");
    }

    /** "example.com" becomes "https://example.com/": people rarely type the scheme. */
    static URI normalize(String url) {
        String withScheme = url.contains("://") ? url : "https://" + url;
        URI uri = URI.create(withScheme);
        if (uri.getHost() == null || !(uri.getScheme().equals("http") || uri.getScheme().equals("https"))) {
            throw new IllegalArgumentException(url);
        }
        return uri.getPath() == null || uri.getPath().isEmpty() ? uri.resolve("/") : uri;
    }

    /** Inside GitHub Actions, also append a Markdown table to the job summary page. */
    private static void writeGithubSummary(Audit audit, Map<String, String> env, PrintStream err) {
        String path = env.get("GITHUB_STEP_SUMMARY");
        if (path == null || path.isBlank()) {
            return;
        }
        try {
            Files.writeString(Path.of(path), new MarkdownReport().render(audit),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            err.println("Warning: could not write GitHub step summary: " + e.getMessage());
        }
    }

    private static int usage(PrintStream err, String problem) {
        err.println(problem);
        err.println();
        err.print(USAGE);
        return ERROR;
    }

    /** Unchecked wrapper so the scanner can be passed around as a plain Function. */
    static final class ScanFailed extends RuntimeException {
        ScanFailed(Throwable cause) {
            super(cause);
        }
    }
}
