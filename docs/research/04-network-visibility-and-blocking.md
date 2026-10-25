# 04 — Network Visibility, Attribution and Blocking

**Research status:** platform/standards review, 25 October 2026  
**Decision this note supports:** implement real blocking and useful telemetry without selling packet inspection as content decryption.

## 1. The visibility ladder

A local packet tunnel may see different levels of information depending on routing, DNS configuration, protocol and server setup. These levels must remain distinct in schema and UI.

1. **IP flow:** destination IP, port, protocol, byte counts and timing. It may be insufficient to distinguish services behind a shared CDN/IP.
2. **DNS hostname:** available when a DNS query is visible to the tunnel. System DNS may be outside the tunnel, cached or encrypted; app-level DNS-over-HTTPS/over-TLS can bypass plaintext DNS inspection.
3. **TLS handshake metadata:** some handshakes may expose SNI or other handshake properties. Do not assume this is always visible.
4. **Encrypted application payload:** HTTPS/TLS and other encrypted protocols generally conceal content from a packet tunnel. PrivaCage must not claim to read precise request bodies or know which personal fields were sent.
5. **Endpoint-side data:** only the service controls server logs/database and what it does with received data. A local phone app cannot inspect this private system.

### Standards change the ceiling

RFC 8484 specifies DNS queries over HTTPS (DoH), which protects DNS query-response exchanges within HTTPS ([S15](SOURCES.md#s15)). In March 2026, the IETF published RFC 9849 for TLS Encrypted Client Hello (ECH). ECH encrypts sensitive portions of the TLS ClientHello, including SNI, when supported; the RFC notes that other channels—such as plaintext DNS or visible IP addresses—can still reveal information ([S16](SOURCES.md#s16)). Therefore, any hostname detection model must be protocol-aware and time-versioned.

## 2. Per-app attribution

Attribution is a separate operation from domain classification. For Android, `ConnectivityManager.getConnectionOwnerUid()` supports TCP/UDP connection ownership under a specified active VPN context, but may return an invalid UID when the connection is not found ([S04](SOURCES.md#s04)). A hostname match must not be used to guess an app. On iOS, attribution varies by Network Extension provider type and configuration.

Required event fields:

```json
{
  "event_type": "network_connection",
  "timestamp": "RFC3339 timestamp",
  "platform": "android",
  "app_uid": null,
  "app_id": null,
  "attribution": "unknown",
  "remote_ip": "192.0.2.10",
  "remote_port": 443,
  "protocol": "tcp",
  "hostname": null,
  "hostname_source": "unavailable",
  "rule_id": null,
  "decision": "observed_only",
  "evidence_confidence": "limited"
}
```

The values above are schema examples only, not an actual observation. Null values are preferable to inventing attribution. The event store must identify source, mapping method, timestamp quality, rule version and whether the VPN was active.

## 3. Domain classification

A domain list can be based on exact hostnames, suffix patterns, IP ranges or known SDK signatures. Each match should carry metadata:

- evidence URL/source, first/last verified date, maintainer and license;
- exact matching rule and version;
- classification type (advertising, analytics, crash reporting, social embed, telemetry, unknown);
- confidence and known overlap with core service functionality;
- expected false-positive/false-negative behavior;
- expiration/review policy and a way to report mistakes.

Do not classify every domain operated by an ad-tech company as malicious. An app can require an analytics endpoint for login or crashes; conversely, a first-party domain can collect telemetry. Labels should describe evidence and likely role rather than accuse the developer.

## 4. Blocking design

Block decisions should be deterministic, auditable and reversible. Prefer a local ruleset with explicit allow/deny precedence and clear user ownership. DNS blocking alone is incomplete: encrypted DNS, hard-coded IPs, alternate resolvers, domain fronting or shared hosting can reduce its effectiveness. IP blocking can break unrelated services hosted behind the same infrastructure. A local VPN can also interfere with other VPNs and filtering tools.

Recommended rule model:

- `scope`: whole device or a specific app only when attribution/configuration is genuinely supported;
- `match`: exact hostname, suffix, IP/CIDR or signature; never hidden ambiguous matching;
- `action`: allow, block, observe-only;
- `reason`: evidence source plus user-facing explanation;
- `created_by`: user, curated list, or temporary safe default;
- `created_at`, `updated_at`, `expires_at`, `database_version`;
- `precedence`: deterministic documented order;
- `last_match`: local timestamp/count without storing payload;
- `failure_mode`: what happens when DNS lookup or classification is unavailable.

For a rule that blocks a shared domain, show the possible breakage and allow a temporary override. Do not enable destructive blocking by a vague risk score alone.

## 5. Fail-open versus fail-closed

- **Fail-open:** if PrivaCage stops, ordinary networking continues. This improves availability but provides no protection during downtime.
- **Fail-closed:** network access is intentionally unavailable unless it passes through the configured enforcement path. This is stronger but can strand users offline if the app or rules fail.

The app must not silently change the user's selected behavior. For each state, show VPN status, last successful packet processing, ruleset age, whether bypass/exclusions exist, and whether filtering is actually active. “Connected to VPN” and “tracker blocking succeeded” are not synonymous.

## 6. DNS and encrypted traffic edge cases

Tests must include DNS cache hits, DoH/DoT, VPN DNS servers, app-specific DNS, IPv6, QUIC/UDP 443, TLS 1.3, ECH when available, shared CDN IPs, captive portals, network changes and a device with another VPN present. If a host name cannot be established, display the IP address and the uncertainty rather than infer from a reverse DNS lookup or threat list.

No TLS interception or custom root certificate should be used as a quiet workaround. HTTPS MITM increases trust risk, breaks certificate pinning, may expose credentials and private content, and is unacceptable as a default privacy feature. If any diagnostic decryption concept is ever considered, it needs a separate explicit consent/security review and is outside the proposed baseline.

## 7. Normal and verbose logs

Normal mode: “A connection to `telemetry.example` matched a community analytics rule and was blocked.” Include “hostname observed via DNS” or “IP-only observation” when it matters.

Verbose mode: packet tuple, event source, UID mapping result, exact rule ID/version, protocol, monotonic/wall-clock timestamp details, and decision latency. Redact payloads completely. Do not store clipboard values, URLs with query strings, HTTP headers, authentication tokens or exact coordinates in either mode.

## 8. Acceptance criteria

- For controlled fixtures, a matching packet is dropped only if an active rule says to block it.
- A rule outcome is logged only after the network path confirms the decision actually occurred.
- Hostnames are stored with their source; IP-only observations remain IP-only.
- Tests detect IPv6 and non-DNS escape paths in the supported configuration.
- Unknown app attribution is never converted into an app-specific event.
- The UI distinguishes “observed,” “matched,” “blocked,” “connection failed” and “not visible.”
- No payload decryption or raw content logging is performed by default.