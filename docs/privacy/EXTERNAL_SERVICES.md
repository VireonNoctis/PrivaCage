# External Services and Data Flows

**Version:** 0.1-draft  
**Prepared:** 3 November 2026

This inventory separates requests made for a user-requested feature from product telemetry. The app must not add a new external recipient without updating this document and the Privacy Policy.

## 1. DNS resolver

The user supplies the resolver address. While DNS filtering is active, supported domain queries are sent to that resolver. The resolver can see the query name, record type and the network source address as observed by the resolver. DNS-over-TLS protects the connection in transit and verifies the certificate hostname but does not hide query contents from the resolver.

The feature is DNS-only and does not capture arbitrary HTTPS, app-owned DoH/DoQ, direct-IP or all IPv6 traffic. This is not a full-device VPN.

## 2. Sync relay

The user configures a relay URL, space and capability. Device messages are signed and recipient-encrypted before upload. The relay transports and stores opaque packets, not readable profile contents.

The relay nevertheless sees message IDs, space IDs, public device cards/fingerprints, timestamps/cursors, payload lengths, access patterns and member-mode request authentication metadata. It receives bearer capabilities in request headers but stores only SHA-256 capability hashes. It stores encrypted message bytes for seven days and request nonces for five minutes, with startup and 60-second cleanup sweeps. SQLite secure-delete is enabled for ordinary table deletions, but this does not guarantee physical erasure from WAL frames, filesystem snapshots, storage-level backups or copied database files.

The repository relay binds to loopback and the application source does not persist client IP addresses or log request bodies/headers. A public deployment needs a separately secured TLS reverse proxy. The proxy/host may see source IP addresses and ordinary connection metadata, and may log paths, headers, body sizes or request timing according to its own configuration. The deployment operator must secure TLS termination, administrator credentials, access controls, backups and its own privacy notice.

## 3. Browser, app store and source links

App-policy URLs, source evidence, legal references and app-store pages open through Android's system browser or an installed app. The destination receives the ordinary connection metadata and any information the user supplies there. PrivaCage does not intercept the browser session, fetch policy contents or crawl private app screens. Only policy URLs and review status are retained in the local encrypted review queue.

## 4. Web workspace

The Svelte web workspace presents the embedded tracker catalogue and derived catalogue information through a Rust/Axum API. The API defaults to 127.0.0.1 and does not ingest live device activity. It contains no product analytics SDK. A public deployment changes the exposure: the deployment operator must assess authentication, TLS, rate limits, host logging and access to any reverse-proxy logs.

## 5. No third-party telemetry vendors

No analytics, advertising, attribution, session-replay or remote crash-reporting vendor is intentionally integrated into the Android client. The Go validate-android-privacy command scans Android build files, manifests and app source for known SDK and advertising-ID markers. This is a static regression check, not proof against every possible hand-written telemetry implementation or platform-level diagnostic.
