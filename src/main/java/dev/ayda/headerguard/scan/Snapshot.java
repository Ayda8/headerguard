package dev.ayda.headerguard.scan;

import java.net.URI;
import java.time.Instant;

/**
 * Everything the checks need to know about a site, captured once by the {@link Scanner}.
 * Checks are pure functions of a snapshot, which keeps them easy to unit test without a network.
 *
 * @param requested            the URL the user asked for
 * @param finalUri             where redirects ended up
 * @param status               HTTP status of the final response
 * @param headers              headers of the final response
 * @param tls                  TLS details, or {@code null} for plain HTTP
 * @param httpRedirectsToHttps whether {@code http://host} redirects to HTTPS; {@code null} if unknown
 * @param corsProbe            headers returned when the request carried a foreign {@code Origin}
 * @param scannedAt            when the scan happened (used for certificate expiry)
 */
public record Snapshot(
        URI requested,
        URI finalUri,
        int status,
        Headers headers,
        TlsInfo tls,
        Boolean httpRedirectsToHttps,
        Headers corsProbe,
        Instant scannedAt) {

    /** The fake origin sent in the CORS probe. Uses the reserved .invalid TLD so it can never be real. */
    public static final String PROBE_ORIGIN = "https://headerguard-probe.invalid";

    public boolean isHttps() {
        return "https".equalsIgnoreCase(finalUri.getScheme());
    }
}
