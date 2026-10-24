# PrivaCage opaque sync relay

This Rust service stores signed encrypted sync packets without decrypting them. It is an early transport component, not an account service or complete sync product.

## Runtime

Requires Rust 1.85+. The service requires an admin bearer token of at least 32 characters and defaults to loopback-only HTTP.

```sh
export PCAGE_RELAY_ADMIN_TOKEN='<long random admin token>'
export PCAGE_RELAY_DB='./data/pcage-sync-relay.sqlite3'
export PCAGE_RELAY_LISTEN='127.0.0.1:8788'
cargo run --manifest-path shared/rust/pcage-sync-relay/Cargo.toml --release
```

Never expose the plain HTTP listener directly to the network. It deliberately refuses non-loopback bind addresses. For remote clients, configure a TLS reverse proxy on the same host and forward to `127.0.0.1:8788`. Protect the database file and its backups.

## API

- `GET /healthz` — process health only.
- `POST /v1/spaces` — admin bearer token; JSON body `{"space_id":"device-space-0001","capability_token":"<64 lowercase hex characters>" }`.
- `POST /v1/spaces/{space_id}/rotate` — admin bearer token; replace the space capability immediately.
- `DELETE /v1/spaces/{space_id}` — admin bearer token; delete the space and queued messages.
- `PUT /v1/spaces/{space_id}/messages/{message_id}` — space capability bearer token; raw serialized sync packet body.
- `GET /v1/spaces/{space_id}/messages?after=0` — space capability bearer token; cursor page of up to 100 records. Payloads are returned as lowercase hex in `payload_hex`.

Space IDs use 8–80 ASCII letters, digits, underscores, or hyphens. Message IDs must be the 32-character lowercase hex IDs used by the protocol. Capability tokens must be 64 lowercase hex characters and should be generated from 32 cryptographically random bytes. The admin token and space capability are distinct secrets.

## Data handling and limits

- SQLite stores the capability hash, opaque packet bytes, cursor, and timestamps; it does not store capability tokens.
- Packets are limited to 2 MiB; each space holds at most 10,000 non-expired packets.
- Stored packets expire after seven days; expired records are purged on reads and writes.
- Duplicate message IDs within one space are rejected.
- Space capability rotation invalidates the old shared capability. It does not selectively revoke one device.
- The relay does not parse or verify packet signatures and cannot prove clients encrypted payloads correctly. Clients must verify packet signatures, fingerprints, recipient binding, expiry, and replay protection.
- Metadata such as space ID, message ID, timing, payload length, and access patterns remains visible to the relay operator.
- No app integration, rate-limiting system, account identity, group roster, or per-device revocation is implemented.
