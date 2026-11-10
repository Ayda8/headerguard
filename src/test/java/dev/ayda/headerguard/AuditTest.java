package dev.ayda.headerguard;

import dev.ayda.headerguard.check.Check;
import dev.ayda.headerguard.check.Snap;
import dev.ayda.headerguard.scan.Snapshot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditTest {

    static final String[] HARDENED = {
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
            "X-Content-Type-Options", "nosniff",
            "Referrer-Policy", "strict-origin-when-cross-origin",
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()",
            "Set-Cookie", "SESSION=x; Path=/; Secure; HttpOnly; SameSite=Lax",
            "Server", "nginx"};

    @Test
    void hardenedSiteGetsFullMarks() {
        Audit audit = Audit.run(Snap.https().headers(HARDENED).build(), Check.defaults());
        assertEquals(100, audit.score());
        assertEquals("A", audit.grade());
        assertTrue(audit.findings().isEmpty());
    }

    @Test
    void bareHttpsSiteLosesPointsForEveryMissingHeader() {
        Audit audit = Audit.run(Snap.https().build(), Check.defaults());
        // HSTS 15 + CSP 8 + framing 8 + nosniff 3 + referrer 3 + permissions 3 = 40
        assertEquals(60, audit.score());
        assertEquals("D", audit.grade());
    }

    @Test
    void criticalFindingForcesGradeF_evenWithAHighScore() {
        Audit audit = Audit.run(Snap.https().headers(HARDENED).cors(
                "Access-Control-Allow-Origin", Snapshot.PROBE_ORIGIN,
                "Access-Control-Allow-Credentials", "true").build(), Check.defaults());
        assertEquals(70, audit.score());
        assertEquals("F", audit.grade());
    }

    @Test
    void findingsAreSortedMostSevereFirst() {
        Audit audit = Audit.run(Snap.http().build(), Check.defaults());
        assertEquals("transport.plain-http", audit.findings().get(0).id());
    }

    @Test
    void scoreNeverGoesBelowZero() {
        Snap terrible = Snap.http().headers(
                "Set-Cookie", "a=1", "Set-Cookie", "b=2", "Set-Cookie", "c=3", "Set-Cookie", "d=4",
                "Server", "Apache/2.4.1", "X-Powered-By", "PHP/5.6", "Referrer-Policy", "unsafe-url")
                .cors("Access-Control-Allow-Origin", Snapshot.PROBE_ORIGIN, "Access-Control-Allow-Credentials", "true");
        assertEquals(0, Audit.run(terrible.build(), Check.defaults()).score());
    }
}
