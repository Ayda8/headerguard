package dev.ayda.headerguard;

import dev.ayda.headerguard.check.Snap;
import dev.ayda.headerguard.scan.Snapshot;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainTest {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(Map<String, String> env, Function<URI, Snapshot> scanner, String... args) {
        return Main.run(args, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8), env, scanner);
    }

    private int run(String... args) {
        return run(Map.of("NO_COLOR", "1", "HEADERGUARD_ASCII", "1"), uri -> Snap.https().build(), args);
    }

    private String out() {
        return out.toString(StandardCharsets.UTF_8);
    }

    @Test
    void addsHttpsWhenSchemeIsMissing() {
        assertEquals(URI.create("https://example.com/"), Main.normalize("example.com"));
        assertEquals(URI.create("http://localhost:8080/api"), Main.normalize("http://localhost:8080/api"));
    }

    @Test
    void textReportShowsGrade() {
        assertEquals(Main.OK, run("example.test"));
        assertTrue(out().contains("Grade D"), out());
        assertTrue(out().contains("x Strict-Transport-Security"), "ASCII mode uses x instead of a cross");
        assertTrue(!out().contains("\u001B["), "NO_COLOR must disable ANSI codes");
    }

    @Test
    void errorStatusIsCalledOut() {
        run(Map.of("NO_COLOR", "1"), uri -> {
            Snapshot ok = Snap.https().build();
            return new Snapshot(ok.requested(), ok.finalUri(), 403, ok.headers(), ok.tls(),
                    ok.httpRedirectsToHttps(), ok.corsProbe(), ok.scannedAt());
        }, "example.test");
        assertTrue(out().contains("answered HTTP 403"), out());
    }

    @Test
    void failUnderGivesExitCodeOneForCi() {
        assertEquals(Main.BELOW_THRESHOLD, run("example.test", "--fail-under", "80"));
        assertEquals(Main.OK, run("example.test", "--fail-under", "60"));
    }

    @Test
    void jsonOutput() {
        run("example.test", "--format", "json");
        assertTrue(out().contains("\"score\": 60"), out());
        assertTrue(out().contains("\"id\": \"hsts.missing\""));
    }

    @Test
    void badArgumentsGiveExitCodeTwo() {
        assertEquals(Main.ERROR, run());
        assertEquals(Main.ERROR, run("example.test", "--fail-under", "abc"));
        assertEquals(Main.ERROR, run("example.test", "--format", "xml"));
        assertEquals(Main.ERROR, run("ftp://example.test"));
    }

    @Test
    void networkErrorGivesExitCodeTwo() {
        int code = run(Map.of(), uri -> {
            throw new Main.ScanFailed(new IOException("connection refused"));
        }, "example.test");
        assertEquals(Main.ERROR, code);
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("connection refused"));
    }

    @Test
    void writesGithubStepSummaryWhenRunningInActions(@TempDir Path dir) throws IOException {
        Path summary = dir.resolve("summary.md");
        run(Map.of("NO_COLOR", "1", "GITHUB_STEP_SUMMARY", summary.toString()),
                uri -> Snap.https().build(), "example.test");
        String md = Files.readString(summary);
        assertTrue(md.startsWith("## headerguard: grade D (60/100)"), md);
        assertTrue(md.contains("| HIGH | Strict-Transport-Security header is missing |"));
    }
}
