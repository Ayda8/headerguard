<div align="center">

# 🛡️ headerguard

**Grade any website's HTTP security in one command, and stop insecure deploys in CI.**

[![CI](https://github.com/Ayda8/headerguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Ayda8/headerguard/actions/workflows/ci.yml)
![Java 21](https://img.shields.io/badge/Java-21-4F46E5?style=flat-square&logo=openjdk&logoColor=white)
![Zero dependencies](https://img.shields.io/badge/runtime%20deps-0-0F766E?style=flat-square)
![License MIT](https://img.shields.io/badge/license-MIT-DB2777?style=flat-square)

</div>

```text
$ java -jar headerguard.jar my-app.example

headerguard · https://my-app.example/
HTTP 200 · TLSv1.3

  ✓ Transport (HTTPS / TLS)
  ✗ Strict-Transport-Security
      HIGH     Strict-Transport-Security header is missing
               fix: Add: Strict-Transport-Security: max-age=31536000; includeSubDomains
  ✓ Content-Security-Policy
  ✓ Clickjacking protection
  ✓ X-Content-Type-Options
  ✓ Referrer-Policy
  ✗ Permissions-Policy
      LOW      Permissions-Policy header is missing
               fix: Turn off features you don't use, e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()
  ✗ Cookies
      MEDIUM   Cookie 'SESSION' is missing Secure, so it can leak over plain HTTP
               fix: Add the Secure attribute to SESSION.
  ✓ CORS
  ✓ Information disclosure

Grade C  ·  score 74/100   (0 critical, 1 high, 1 medium, 1 low)
```

Every finding comes with **the exact fix**, not just a red cross.

## What it checks

| Area | What it looks for | Why it matters |
|---|---|---|
| **Transport** | HTTPS, HTTP→HTTPS redirect, legacy TLS 1.0/1.1, certificate expiry | Traffic can be read or changed in transit |
| **HSTS** | `Strict-Transport-Security`, `max-age` ≥ 180 days, `includeSubDomains` | Stops SSL-stripping downgrades |
| **CSP** | `Content-Security-Policy`, `'unsafe-inline'`, `'unsafe-eval'`, wildcard script hosts | Main browser-side defence against XSS |
| **Clickjacking** | `frame-ancestors` or `X-Frame-Options` | Stops your page being framed invisibly |
| **MIME sniffing** | `X-Content-Type-Options: nosniff` | Stops browsers running files as scripts |
| **Referrer** | `Referrer-Policy`, leaky `unsafe-url` | Keeps tokens in URLs from leaking to other sites |
| **Permissions** | `Permissions-Policy` | Locks down camera, microphone, geolocation |
| **Cookies** | `Secure`, `HttpOnly`, `SameSite` on every cookie | Session theft and CSRF |
| **CORS** | Sends a fake foreign `Origin` and checks if it's trusted, especially with credentials | A reflected origin + credentials lets **any site read your users' data** |
| **Disclosure** | Versioned `Server`, `X-Powered-By` | Tells attackers exactly which CVEs to try |

Scoring: start at 100; CRITICAL −30, HIGH −15, MEDIUM −8, LOW −3. **Any CRITICAL finding means grade F**, however good the rest is, because one open door is enough.

## Use it

### Command line

```bash
mvn -B package                      # builds target/headerguard.jar
java -jar target/headerguard.jar example.com
java -jar target/headerguard.jar example.com --format json
java -jar target/headerguard.jar example.com --fail-under 80   # exit code 1 if score < 80
```

| Exit code | Meaning |
|---|---|
| `0` | Scan finished (and score ≥ `--fail-under`, if given) |
| `1` | Score below `--fail-under` |
| `2` | Bad arguments or the site couldn't be reached |

### Docker

```bash
docker build -t headerguard .
docker run --rm headerguard example.com
```

The image is multi-stage: Maven builds and **tests** in the first stage, and the final image is a JRE plus one jar, running as a non-root user.

### GitHub Action

Fail a deploy pipeline when your staging site's security headers regress:

```yaml
- uses: Ayda8/headerguard@v0.1.0
  with:
    url: https://staging.my-app.example
    fail-under: 80
```

Inside Actions, headerguard also writes a Markdown table to the **job summary** page, so the results are readable without opening logs.

## How it's built

```
Scanner ──► Snapshot ──► Check × 10 ──► Audit (score, grade) ──► Report (text / json / markdown)
 network     plain data    pure rules       plain logic              presentation
```

- **One class touches the network.** `Scanner` sends at most three ordinary `GET` requests (the page, the page with a probe `Origin`, and the `http://` version) and records the results in an immutable `Snapshot`.
- **Checks are pure functions** of a snapshot: no I/O, no clock. That's why each rule has fast, exact unit tests, and adding a new check means adding one class to `Check.defaults()`.
- **Zero runtime dependencies.** Only the JDK (`java.net.http.HttpClient`); JUnit is test-only. A small attack surface for a security tool.
- **Scanner tests use a real local HTTP server** (including a deliberately vulnerable CORS endpoint), so the network code is tested without the internet.
- The CORS probe uses a `.invalid` origin, a TLD reserved so it can never belong to anyone.

## Responsible use

headerguard only sends normal page requests, the same as a browser visit. Still: **scan sites you own or have permission to test.**

## Roadmap

- [ ] Scan a list of URLs and output a comparison table
- [ ] Config file to ignore accepted findings (e.g. a public API that intentionally uses `*` CORS)
- [ ] SARIF output, so findings show up in GitHub code scanning
- [ ] Check `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy`

## License

MIT © Aida Kabiri
