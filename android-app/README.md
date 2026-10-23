# PrivaCage Android app adapter

This is the first Android platform adapter for the pure Kotlin/JVM DNS core in `../android-core`.

## Implemented

- Local UI for a numeric IPv4 upstream resolver and user-entered blocked domains.
- Bundles the canonical `shared/tracker-db/signatures.json` directly as an Android asset; it does not duplicate the database.
- Displays tracker records with evidence URLs, confidence, review status, and verification dates.
- Lets users explicitly import only `active` domain indicators into the rule editor; changes still require saving. `review` and `retired` records are never imported by this action, and SDK class patterns are informational only.
- Local-only settings in Android SharedPreferences.
- Explicit `VpnService.prepare()` consent.
- A `VpnService` with a virtual DNS address and a route only to that address.
- A blocking TUN read/write loop that processes supported IPv4 UDP DNS packets and returns responses.
- Protected upstream UDP and TCP sockets using `VpnService.protect`; upstream TCP is retried when a valid UDP response sets the DNS TC flag.
- A foreground notification and explicit handling of tunnel I/O/processing errors.
- A failed upstream query is dropped without intentionally shutting down the whole VPN tunnel.

## Build

Requires JDK 17, Android SDK platform 36, and Gradle 8.14 or compatible.

    gradle assembleDebug
    gradle :android-core:test

The debug APK is generated at `app/build/outputs/apk/debug/app-debug.apk`.

## Limits

- The bundled catalog currently contains only two Analytics endpoint indicators and is not comprehensive. Only explicitly imported active domain indicators (plus manually entered domains) become blocking rules; review-status records are excluded.
- The client-facing tunnel supports IPv4 UDP DNS only. It does not accept DNS-over-TCP connections from device apps.
- Upstream DNS uses ordinary UDP/TCP to the user-selected resolver, not encrypted DNS.
- If a complete TCP response is too large to fit into the client-facing UDP packet, the query fails rather than producing a fabricated answer.
- Queries are processed sequentially; a slow resolver delays later requests.
- The service does not attribute queries to apps or inspect HTTPS contents.
- IPv6 DNS, DoH, DoT, and DoQ are not filtered.
- This code has not been tested on an emulator or physical device. CI and device validation are required before calling it release-ready.
- Catalog parsing is strict and fails visibly in the UI if its schema is invalid; manual rules remain usable. The catalog is bundled at build time, not remotely updated.
- Platform/device policy can prevent VPN or foreground-service startup. Failures stop the service; DNS query names are not logged.
