package dev.ayda.headerguard.scan;

import java.io.IOException;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * The only class that touches the network. It sends at most three ordinary GET requests
 * (the page, the page with a foreign Origin, and the http:// version) and records what came back.
 */
public final class Scanner {

    static final String USER_AGENT = "headerguard/0.1 (+https://github.com/Ayda8/headerguard)";

    private final HttpClient followingClient;
    private final HttpClient nonFollowingClient;
    private final Duration timeout;
    private final Clock clock;

    public Scanner(Duration timeout, Clock clock) {
        this.timeout = timeout;
        this.clock = clock;
        this.followingClient = client(HttpClient.Redirect.NORMAL);
        this.nonFollowingClient = client(HttpClient.Redirect.NEVER);
    }

    public Scanner() {
        this(Duration.ofSeconds(10), Clock.systemUTC());
    }

    private HttpClient client(HttpClient.Redirect redirect) {
        return HttpClient.newBuilder()
                .followRedirects(redirect)
                .connectTimeout(timeout)
                .proxy(ProxySelector.getDefault())
                .build();
    }

    public Snapshot scan(URI target) throws IOException, InterruptedException {
        Instant now = clock.instant();
        HttpResponse<Void> main = followingClient.send(get(target).build(), HttpResponse.BodyHandlers.discarding());
        HttpResponse<Void> cors = followingClient.send(
                get(target).header("Origin", Snapshot.PROBE_ORIGIN).build(),
                HttpResponse.BodyHandlers.discarding());

        Boolean redirects = "https".equalsIgnoreCase(main.uri().getScheme()) ? probeHttpRedirect(main.uri()) : null;

        return new Snapshot(
                target,
                main.uri(),
                main.statusCode(),
                Headers.of(main.headers().map()),
                main.sslSession().map(Scanner::tlsInfo).orElse(null),
                redirects,
                Headers.of(cors.headers().map()),
                now);
    }

    /** Does http://host/ answer with a redirect to an https:// URL? {@code null} when port 80 is unreachable. */
    private Boolean probeHttpRedirect(URI httpsUri) throws InterruptedException {
        URI plain = URI.create("http://" + httpsUri.getHost() + "/");
        try {
            HttpResponse<Void> r = nonFollowingClient.send(get(plain).build(), HttpResponse.BodyHandlers.discarding());
            boolean isRedirect = r.statusCode() >= 300 && r.statusCode() < 400;
            String location = r.headers().firstValue("Location").orElse("");
            return isRedirect && location.toLowerCase().startsWith("https://");
        } catch (IOException e) {
            return null; // many HTTPS-only hosts simply don't listen on port 80, which is fine
        }
    }

    private HttpRequest.Builder get(URI uri) {
        return HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("User-Agent", USER_AGENT)
                .GET();
    }

    private static TlsInfo tlsInfo(SSLSession session) {
        Instant notAfter = null;
        try {
            Certificate[] chain = session.getPeerCertificates();
            if (chain.length > 0 && chain[0] instanceof X509Certificate leaf) {
                notAfter = leaf.getNotAfter().toInstant();
            }
        } catch (SSLPeerUnverifiedException ignored) {
            // leave expiry unknown
        }
        return new TlsInfo(session.getProtocol(), notAfter);
    }
}
