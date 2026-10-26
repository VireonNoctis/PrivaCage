# PrivaCage Web Console

A responsive Svelte 5 + TypeScript console with a separate Rust/Axum API. The browser client is a static Vite build; there are no JavaScript server routes or JavaScript backend processes.

## Stack boundary

- **Frontend:** Svelte 5, TypeScript, Vite, plain CSS.
- **Backend:** Rust, Axum, Tokio, Serde.
- **Canonical tracker data:** shared/tracker-db/signatures.json, embedded into the Rust API at compile time.
- **Local-first behavior:** no account, telemetry SDK, external font request, analytics request, or remote API dependency is introduced by the web client.

## Run locally

From the repository root, start the API:

    cargo run --manifest-path web-backend/Cargo.toml

The API binds to 127.0.0.1:8787 by default. To override the address for a trusted local deployment, set PRIVACAGE_WEB_BIND. Do not bind this unauthenticated API to a public interface.

In a second terminal:

    cd web
    npm install
    npm run dev

Vite binds to 127.0.0.1 and proxies /api/* to the Rust service. The UI never substitutes demo metrics when the API is offline; it shows an explicit unavailable state.

## Validation

    cd web
    npm test
    npm run check
    npm run build

From the repository root:

    cargo test --manifest-path web-backend/Cargo.toml

The API tests verify that summary counts are computed from the bundled source, evidence-linked tracker records are returned, and disconnected device activity remains unavailable.

## Production deployment

Build the static browser app with npm run build. Serve web/dist using a static web server and reverse-proxy same-origin /api/* requests to the Rust service. Keep the Rust service on loopback behind the reverse proxy unless an authenticated transport is deliberately added. There is no authentication or web device-pairing flow in this first web release.

## Implemented screens

- **Overview:** live API reachability and real catalog summary, category distribution, workspace modules, and clear device-connection boundary.
- **Tracker intelligence:** searchable/filterable evidence-linked catalog backed by the Rust API, with local JSON export and domain-copy actions.
- **Activity log:** intentional empty state until a device event source is connected; no invented or sample events.
- **Audit trail:** locally verifies Android signed audit checkpoint JSON (signature, exact payload digest, schema, redaction claims, counters, and every event hash-chain link) without uploading the file.
- **Platform boundaries:** accurate distinction between web catalog availability and platform-local controls.
- **Settings:** motion preference, connection status, catalog version, and privacy posture.

The dashboard's catalog counts describe source-backed database entries, not detected devices, live tracking, or blocked traffic. The Android adapter remains device-local and is not automatically connected to this web workspace.

### Local audit checkpoint verification

The audit screen accepts the Android export format `privacage-audit-checkpoint` schema v1 as a JSON file up to 2 MiB. Verification is performed entirely in the browser with Web Crypto: it validates the embedded P-256 signature, the SHA-256 digest over the exact UTF-8 payload string, strict JSON fields (including duplicate-key rejection), privacy-redaction claims, record accounting, and each SHA-256 event-chain link. The supported payload is capped at 100 records and 1 MiB.

A successful result proves consistency with the public key embedded in that file; it does not identify a person, authenticate the key independently, prove a trusted timestamp, or demonstrate that the source recorded every event. The optional fingerprint field compares the embedded key's SHA-256 fingerprint to a value supplied through a separate trusted channel. The browser never displays event hostnames in the verification summary and does not modify the source file.

The verifier and its schema checks are covered by `npm test`; the regular frontend validation workflow also runs `npm run check` and `npm run build`.
