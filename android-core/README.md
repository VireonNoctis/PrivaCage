# PrivaCage Android DNS policy core

This is the pure Kotlin/JVM DNS engine used by the early Android app adapter in `../android-app`.

## What it does

- Parses a restricted subset of classic DNS queries with exactly one question.
- Validates a single EDNS(0) OPT pseudo-record, including the record's fixed fields and each option's declared length.
- Treats unknown EDNS option payloads as opaque, as required for forward compatibility; it does not interpret or rewrite them.
- Normalizes configured domain rules and matches exact domains or true subdomain suffixes.
- Returns an explicit allow, block, or malformed result.
- Decodes IPv4 UDP packets addressed to port 53, validating IP/UDP lengths and checksums.
- Builds IPv4 UDP replies with reversed endpoints and recalculated checksums.
- Builds DNS REFUSED replies for valid supported queries while preserving the question and omitting additional records.
- Connects the policy evaluator and packet codec in a processor: blocked queries become actual reply packets, malformed queries are dropped, and allowed queries are explicitly returned as requiring forwarding.
- Provides a one-query UDP DNS forwarder that enforces the same policy, invokes a caller-supplied socket-protection callback, applies a bounded timeout, and validates response identity, echoed question, resource-record boundaries, and absence of undeclared trailing bytes.
- Coordinates these pieces in a packet-to-packet engine: blocked queries return a REFUSED packet, allowed queries are forwarded and returned as response packets, malformed queries are dropped, and upstream I/O errors propagate to the caller.

The forwarder opens a real UDP socket when called. The Android adapter provides the VPN service, consent flow, TUN read/write loop, and a `VpnService.protect`-backed upstream socket callback. The app has not yet been validated on a physical device or emulator, and the shared tracker database is not loaded by the app. EDNS support follows the OPT wire format in [RFC 6891, section 6.1.2](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.2).

## Current limits

- The Android VPN adapter is early implementation code and has not yet been verified on an emulator or physical device.
- Only user-entered domains are active; no verified tracker list is bundled or loaded.
- It does not identify which app made a query.
- It rejects compressed query names, multiple questions, answer/authority records in queries, more than one additional record, non-OPT additional records, non-IN question classes, non-ASCII query hostnames, and EDNS versions other than 0.
- The upstream forwarder supports UDP only. It does not retry over TCP after a truncated response; a client that retries TCP to the virtual DNS endpoint is not currently supported.
- It does not filter DNS-over-HTTPS, DNS-over-TLS, or DNS-over-QUIC.
- It has not been tested on a physical Android device.

The next integration stage still needs upstream TCP DNS fallback, a downstream TCP DNS endpoint, a deliberate IPv6 strategy, network-change handling, concurrency/backpressure, and emulator/device tests. RFC 7766 requires general-purpose DNS implementations to support both UDP and TCP; this app must not imply otherwise while only UDP is supported.

## Run tests

Requires JDK 17 and network access for Gradle dependencies:

    gradle test

The repository CI workflow also builds the Android debug APK and runs these tests. Do not treat the app as CI-verified until the corresponding workflow run passes.
