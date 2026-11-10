package dev.ayda.headerguard.scan;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Runs the real HTTP client against a tiny local server: no internet needed. */
class ScannerTest {

    private HttpServer server;
    private URI base;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            var h = exchange.getResponseHeaders();
            h.add("X-Content-Type-Options", "nosniff");
            h.add("Set-Cookie", "a=1; HttpOnly");
            h.add("Set-Cookie", "b=2; HttpOnly");
            String origin = exchange.getRequestHeaders().getFirst("Origin");
            if (origin != null) { // a deliberately vulnerable CORS setup: echo whatever origin arrives
                h.add("Access-Control-Allow-Origin", origin);
                h.add("Access-Control-Allow-Credentials", "true");
            }
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.createContext("/old", exchange -> {
            exchange.getResponseHeaders().add("Location", "/");
            exchange.sendResponseHeaders(301, -1);
            exchange.close();
        });
        server.start();
        base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private Scanner scanner() {
        return new Scanner(Duration.ofSeconds(5), Clock.fixed(Instant.parse("2026-11-10T00:00:00Z"), ZoneOffset.UTC));
    }

    @Test
    void capturesHeadersCookiesAndCorsProbe() throws Exception {
        Snapshot s = scanner().scan(base.resolve("/"));

        assertEquals(200, s.status());
        assertFalse(s.isHttps());
        assertNull(s.tls());
        assertNull(s.httpRedirectsToHttps(), "redirect probe only runs for HTTPS sites");
        assertEquals("nosniff", s.headers().first("x-content-type-options").orElseThrow());
        assertEquals(2, s.headers().all("Set-Cookie").size());
        assertTrue(s.headers().first("Access-Control-Allow-Origin").isEmpty(),
                "the normal request carries no Origin, so no CORS headers");
        assertEquals(Snapshot.PROBE_ORIGIN, s.corsProbe().first("Access-Control-Allow-Origin").orElseThrow());
    }

    @Test
    void followsRedirects() throws Exception {
        Snapshot s = scanner().scan(base.resolve("/old"));
        assertEquals(base.resolve("/"), s.finalUri());
        assertEquals(200, s.status());
    }
}
