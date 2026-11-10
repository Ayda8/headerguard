package dev.ayda.headerguard.check;

import dev.ayda.headerguard.scan.Snapshot;
import dev.ayda.headerguard.scan.TlsInfo;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** HTTPS itself: is it used, is the TLS version modern, is the certificate about to expire. */
public final class TransportCheck implements Check {

    static final Set<String> LEGACY_PROTOCOLS = Set.of("SSLv3", "TLSv1", "TLSv1.1");
    static final Duration EXPIRY_WARNING = Duration.ofDays(14);

    @Override
    public String name() {
        return "Transport (HTTPS / TLS)";
    }

    @Override
    public List<Finding> inspect(Snapshot s) {
        List<Finding> findings = new ArrayList<>();
        if (!s.isHttps()) {
            findings.add(new Finding("transport.plain-http", Severity.HIGH,
                    "Site is served over plain HTTP",
                    "Serve the site over HTTPS (e.g. a free Let's Encrypt certificate) and redirect HTTP to it."));
            return findings;
        }
        if (Boolean.FALSE.equals(s.httpRedirectsToHttps())) {
            findings.add(new Finding("transport.no-redirect", Severity.MEDIUM,
                    "http:// version does not redirect to HTTPS",
                    "Return a 301 from http:// to the https:// URL so nobody lands on the insecure version."));
        }
        TlsInfo tls = s.tls();
        if (tls == null) {
            return findings;
        }
        if (tls.protocol() != null && LEGACY_PROTOCOLS.contains(tls.protocol())) {
            findings.add(new Finding("transport.legacy-tls", Severity.HIGH,
                    "Negotiated legacy protocol " + tls.protocol(),
                    "Disable SSLv3, TLS 1.0 and TLS 1.1 on the server; allow only TLS 1.2 and 1.3."));
        }
        if (tls.certNotAfter() != null) {
            Duration left = Duration.between(s.scannedAt(), tls.certNotAfter());
            if (left.isNegative()) {
                findings.add(new Finding("transport.cert-expired", Severity.CRITICAL,
                        "TLS certificate has expired",
                        "Renew the certificate now, and automate renewal (e.g. certbot or your platform's ACME)."));
            } else if (left.compareTo(EXPIRY_WARNING) < 0) {
                findings.add(new Finding("transport.cert-expiring", Severity.MEDIUM,
                        "TLS certificate expires in " + left.toDays() + " day(s)",
                        "Renew the certificate and check that automatic renewal actually runs."));
            }
        }
        return findings;
    }
}
