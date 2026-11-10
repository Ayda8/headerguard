package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Headers;
import dev.ayda.headerguard.scan.Snapshot;
import dev.ayda.headerguard.scan.TlsInfo;

import java.net.URI;
import java.time.Instant;

/** Test builder for snapshots, so each test states only what matters to it. */
public final class Snap {

    public static final Instant NOW = Instant.parse("2026-11-10T00:00:00Z");

    private String url = "https://example.test/";
    private Headers headers = Headers.empty();
    private Headers cors = Headers.empty();
    private TlsInfo tls = new TlsInfo("TLSv1.3", NOW.plusSeconds(90L * 24 * 3600));
    private Boolean redirects = true;

    public static Snap https() {
        return new Snap();
    }

    public static Snap http() {
        Snap s = new Snap();
        s.url = "http://example.test/";
        s.tls = null;
        s.redirects = null;
        return s;
    }

    public Snap headers(String... nameValuePairs) {
        this.headers = Headers.of(nameValuePairs);
        return this;
    }

    public Snap cors(String... nameValuePairs) {
        this.cors = Headers.of(nameValuePairs);
        return this;
    }

    public Snap tls(TlsInfo tls) {
        this.tls = tls;
        return this;
    }

    public Snap redirects(Boolean redirects) {
        this.redirects = redirects;
        return this;
    }

    public Snapshot build() {
        URI uri = URI.create(url);
        return new Snapshot(uri, uri, 200, headers, tls, redirects, cors, NOW);
    }
}
