package dev.ayda.headerguard.scan;

import java.time.Instant;

/**
 * @param protocol      negotiated protocol, e.g. {@code TLSv1.3}
 * @param certNotAfter  expiry of the leaf certificate, or {@code null} if unavailable
 */
public record TlsInfo(String protocol, Instant certNotAfter) {
}
