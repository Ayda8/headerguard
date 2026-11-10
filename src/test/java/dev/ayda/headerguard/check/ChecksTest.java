package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;
import dev.ayda.headerguard.scan.TlsInfo;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChecksTest {

    private static List<String> ids(Check check, Snap snap) {
        return check.inspect(snap.build()).stream().map(Finding::id).toList();
    }

    @Nested
    class Transport {
        TransportCheck check = new TransportCheck();

        @Test
        void plainHttpIsHigh() {
            List<Finding> f = check.inspect(Snap.http().build());
            assertEquals(List.of("transport.plain-http"), f.stream().map(Finding::id).toList());
            assertEquals(Severity.HIGH, f.get(0).severity());
        }

        @Test
        void modernTlsWithValidCertPasses() {
            assertEquals(List.of(), ids(check, Snap.https()));
        }

        @Test
        void legacyTlsIsFlagged() {
            assertEquals(List.of("transport.legacy-tls"),
                    ids(check, Snap.https().tls(new TlsInfo("TLSv1.1", Snap.NOW.plusSeconds(864_000_0)))));
        }

        @Test
        void expiredCertIsCritical() {
            List<Finding> f = check.inspect(Snap.https().tls(new TlsInfo("TLSv1.3", Snap.NOW.minusSeconds(60))).build());
            assertEquals(Severity.CRITICAL, f.get(0).severity());
        }

        @Test
        void certExpiringWithinTwoWeeksIsWarned() {
            assertEquals(List.of("transport.cert-expiring"),
                    ids(check, Snap.https().tls(new TlsInfo("TLSv1.3", Snap.NOW.plusSeconds(3L * 24 * 3600)))));
        }

        @Test
        void missingHttpToHttpsRedirectIsFlagged_butUnknownIsNot() {
            assertEquals(List.of("transport.no-redirect"), ids(check, Snap.https().redirects(false)));
            assertEquals(List.of(), ids(check, Snap.https().redirects(null)));
        }
    }

    @Nested
    class Hsts {
        HstsCheck check = new HstsCheck();

        @Test
        void missingIsHigh() {
            assertEquals(List.of("hsts.missing"), ids(check, Snap.https()));
        }

        @Test
        void strongPolicyPasses() {
            assertEquals(List.of(), ids(check, Snap.https()
                    .headers("strict-transport-security", "max-age=31536000; includeSubDomains; preload")));
        }

        @Test
        void shortMaxAgeAndNoSubdomains() {
            assertEquals(List.of("hsts.short-max-age", "hsts.no-subdomains"),
                    ids(check, Snap.https().headers("Strict-Transport-Security", "max-age=3600")));
        }

        @Test
        void garbageMaxAgeIsInvalid() {
            assertTrue(ids(check, Snap.https().headers("Strict-Transport-Security", "max-age=forever"))
                    .contains("hsts.invalid"));
        }

        @Test
        void ignoredOnPlainHttp() {
            assertEquals(List.of(), ids(check, Snap.http()));
        }
    }

    @Nested
    class Csp {
        CspCheck check = new CspCheck();

        @Test
        void missing() {
            assertEquals(List.of("csp.missing"), ids(check, Snap.https()));
        }

        @Test
        void strictPolicyPasses() {
            assertEquals(List.of(), ids(check, Snap.https()
                    .headers("Content-Security-Policy", "default-src 'self'; object-src 'none'")));
        }

        @Test
        void unsafeInlineAndEvalAreFlagged() {
            assertEquals(List.of("csp.unsafe-inline", "csp.unsafe-eval"), ids(check, Snap.https()
                    .headers("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'unsafe-eval'")));
        }

        @Test
        void unsafeInlineWithNonceIsAcceptable() {
            // CSP2+ browsers ignore 'unsafe-inline' when a nonce is present; it is only a fallback for old ones
            assertEquals(List.of(), ids(check, Snap.https()
                    .headers("Content-Security-Policy", "script-src 'nonce-abc123' 'unsafe-inline'")));
        }

        @Test
        void wildcardScriptSource() {
            assertEquals(List.of("csp.wildcard-source"), ids(check, Snap.https()
                    .headers("Content-Security-Policy", "default-src *")));
        }

        @Test
        void policyWithoutScriptControl() {
            assertEquals(List.of("csp.no-script-policy"), ids(check, Snap.https()
                    .headers("Content-Security-Policy", "frame-ancestors 'none'")));
        }
    }

    @Nested
    class Framing {
        FramingCheck check = new FramingCheck();

        @Test
        void unprotected() {
            assertEquals(List.of("framing.unprotected"), ids(check, Snap.https()));
        }

        @Test
        void xFrameOptionsOrFrameAncestorsProtect() {
            assertEquals(List.of(), ids(check, Snap.https().headers("X-Frame-Options", "deny")));
            assertEquals(List.of(), ids(check, Snap.https()
                    .headers("Content-Security-Policy", "frame-ancestors 'self'")));
        }

        @Test
        void allowFromIsNotProtection() {
            assertEquals(List.of("framing.unprotected"),
                    ids(check, Snap.https().headers("X-Frame-Options", "ALLOW-FROM https://a.test")));
        }
    }

    @Nested
    class SmallHeaders {
        @Test
        void contentTypeOptions() {
            assertEquals(List.of("xcto.missing"), ids(new ContentTypeOptionsCheck(), Snap.https()));
            assertEquals(List.of(), ids(new ContentTypeOptionsCheck(),
                    Snap.https().headers("X-Content-Type-Options", "nosniff")));
        }

        @Test
        void referrerPolicy() {
            ReferrerPolicyCheck check = new ReferrerPolicyCheck();
            assertEquals(List.of("referrer.missing"), ids(check, Snap.https()));
            assertEquals(List.of("referrer.leaky"), ids(check, Snap.https().headers("Referrer-Policy", "unsafe-url")));
            assertEquals(List.of(), ids(check, Snap.https()
                    .headers("Referrer-Policy", "unsafe-url, strict-origin-when-cross-origin")));
        }

        @Test
        void permissionsPolicy() {
            assertEquals(List.of("permissions.missing"), ids(new PermissionsPolicyCheck(), Snap.https()));
            assertEquals(List.of(), ids(new PermissionsPolicyCheck(),
                    Snap.https().headers("Permissions-Policy", "camera=()")));
        }
    }

    @Nested
    class Cookies {
        CookieCheck check = new CookieCheck();

        @Test
        void wellConfiguredCookiePasses() {
            assertEquals(List.of(), ids(check, Snap.https()
                    .headers("Set-Cookie", "SESSION=abc; Path=/; Secure; HttpOnly; SameSite=Lax")));
        }

        @Test
        void bareCookieGetsAllThreeFindings() {
            assertEquals(List.of("cookie.no-secure", "cookie.no-httponly", "cookie.no-samesite"),
                    ids(check, Snap.https().headers("Set-Cookie", "SESSION=abc; Path=/")));
        }

        @Test
        void sameSiteNoneNeedsSecure() {
            assertTrue(ids(check, Snap.https().headers("Set-Cookie", "t=1; HttpOnly; SameSite = None"))
                    .contains("cookie.samesite-none-insecure"));
        }

        @Test
        void everyCookieIsChecked() {
            List<Finding> f = check.inspect(Snap.https().headers(
                    "Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Strict",
                    "Set-Cookie", "b=2; Secure; SameSite=Strict").build());
            assertEquals(1, f.size());
            assertTrue(f.get(0).title().contains("'b'"));
        }
    }

    @Nested
    class Cors {
        CorsCheck check = new CorsCheck();

        @Test
        void noCorsHeadersIsFine() {
            assertEquals(List.of(), ids(check, Snap.https()));
        }

        @Test
        void reflectedOriginWithCredentialsIsCritical() {
            List<Finding> f = check.inspect(Snap.https().cors(
                    "Access-Control-Allow-Origin", Snapshot.PROBE_ORIGIN,
                    "Access-Control-Allow-Credentials", "true").build());
            assertEquals("cors.reflected-with-credentials", f.get(0).id());
            assertEquals(Severity.CRITICAL, f.get(0).severity());
        }

        @Test
        void reflectedWithoutCredentialsIsMedium() {
            assertEquals(List.of("cors.reflected"),
                    ids(check, Snap.https().cors("Access-Control-Allow-Origin", Snapshot.PROBE_ORIGIN)));
        }

        @Test
        void publicWildcardWithoutCredentialsIsAllowed() {
            assertEquals(List.of(), ids(check, Snap.https().cors("Access-Control-Allow-Origin", "*")));
        }

        @Test
        void nullOriginWithCredentials() {
            assertEquals(List.of("cors.null-with-credentials"), ids(check, Snap.https().cors(
                    "Access-Control-Allow-Origin", "null", "Access-Control-Allow-Credentials", "true")));
        }
    }

    @Nested
    class Disclosure {
        DisclosureCheck check = new DisclosureCheck();

        @Test
        void versionedServerAndPoweredBy() {
            assertEquals(List.of("disclosure.server-version", "disclosure.x-powered-by"), ids(check, Snap.https()
                    .headers("Server", "nginx/1.18.0", "X-Powered-By", "PHP/8.1")));
        }

        @Test
        void bareServerNameIsFine() {
            assertEquals(List.of(), ids(check, Snap.https().headers("Server", "nginx")));
        }
    }
}
