# PrivaCage Android DNS policy core

This is the pure Kotlin/JVM DNS policy and packet engine used by the early Android VPN adapter in `../android-app`.

## Implemented core

- Parses a deliberately restricted subset of classic DNS queries with exactly one question.
- Validates EDNS(0) OPT fixed fields and declared option lengths. Unknown option payloads stay opaque; PrivaCage does not interpret or rewrite them.
- Normalizes domain rules and matches exact hostnames or DNS-label-boundary subdomains. It does not use arbitrary substring matching.
- Returns explicit allow, block, malformed, unsupported, response, or drop outcomes.
- Decodes IPv4 UDP DNS packets, validates declared lengths and IPv4/UDP checksums, and builds reverse-endpoint replies with recalculated checksums.
- Decodes IPv6 packets with a fixed 40-byte header and directly encapsulated UDP, requires a valid non-zero UDP checksum, validates payload lengths, and rejects jumbograms, extension headers, and unsupported packet shapes instead of attempting to parse them as ordinary UDP DNS.
- Builds a DNS REFUSED response for supported blocked queries while preserving the question and omitting additional records.
- Applies the policy to both supported IP families, returns blocked replies directly, and forwards allowed query payloads through the injected upstream transport.
- Validates upstream DNS response identity, question, resource-record boundaries, compression pointers, and declared lengths. A truncated upstream UDP response can be retried through a protected TCP socket.
- Supports an optional Android DNS-over-TLS transport with platform trust, hostname verification, protected sockets, bounded reads, and no plaintext fallback.
- Records aggregate block/forward/drop/failure counts without retaining DNS names or packet payloads in the core.

The Android adapter obtains explicit `VpnService.prepare()` user consent, establishes virtual IPv4 and IPv6 DNS addresses, routes only those specific DNS endpoints, protects upstream sockets from looping through its own VPN, and owns the TUN lifecycle. The bundled tracker catalogue can be reviewed in-app; only `active` domain indicators can be manually imported into the rule editor, and importing does not save or enable them.

EDNS(0) wire layout follows [RFC 6891 §6.1.2](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.2). DNS implementations' UDP/TCP interoperability requirements are described in [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html).

## Boundaries that remain

- **Not a general VPN/firewall.** Only the configured virtual DNS destinations are routed to this interface. The service does not capture all device traffic or create a device-wide kill switch.
- **Client-facing UDP only.** DNS-over-TCP connections originating from apps are not accepted by this TUN packet processor. TCP is used only for the engine's upstream fallback after a truncated UDP response.
- **IPv6 support is intentionally narrow.** It accepts only direct IPv6/UDP with a valid UDP checksum. IPv6 extension headers, fragment headers, jumbograms, and other upper-layer protocols are rejected. Large response packets that would exceed the 1500-byte TUN MTU are dropped rather than truncated. Fragment reassembly, extension-header traversal, PMTU discovery, and a full IPv6 transport stack are not implemented.
- **Other encrypted DNS bypasses remain possible.** The filter does not decode DNS-over-HTTPS, DNS-over-QUIC, or arbitrary application tunnels. DNS-over-TLS can be selected as PrivaCage's own upstream, but that does not force unrelated applications to use that resolver.
- **Direct-IP connections are outside DNS policy.** An application can connect to a literal IP address without making a DNS query through this engine.
- **No reliable app attribution.** A local VPN sees packets at the virtual interface but this implementation does not reliably map each query to the originating app.
- **No DNS-name logging in the core.** Android has a separate, explicitly opt-in, bounded local history. Its socket-owner attribution is best effort and may name an Android resolver/system process rather than the originating application.
- **No silent fail-open.** Invalid packets are dropped. Upstream timeouts/errors drop that query and are surfaced in counters/status; fabricated DNS answers are not created to hide a failure.
- **Not device-verified yet.** Unit tests cover selected packet and policy cases, but do not prove Android routes both address families as expected on every OEM build. Emulator/physical-device validation remains required for VPN permission/revocation, IPv4/IPv6 routing, resolver compatibility, network changes, captive portals, lifecycle termination, and real application traffic.
- **No claims of absolute privacy.** A match identifies a known endpoint/class marker, not maliciousness, the initiating app, or proof that personal data was transmitted. A missing match is not evidence of no tracking.

## Run tests

Requires JDK 17 and Gradle with access to declared dependencies:

```sh
cd android-app
gradle :android-core:test
gradle :app:testDebugUnitTest
gradle assembleDebug
```

Tests are only considered passing when the associated command or the repository's CI workflow actually completes successfully. The addition of a unit-tested packet codec does not by itself certify VPN behavior on a real device.
