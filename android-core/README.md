# PrivaCage Android DNS policy core

This is an isolated Kotlin/JVM policy library, not an Android application or VPN service.

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
- Provides a one-query UDP DNS forwarder that enforces the same policy, invokes a caller-supplied socket-protection callback, applies a bounded timeout, and checks the response ID and echoed question.
- Coordinates these pieces in a packet-to-packet engine: blocked queries return a REFUSED packet, allowed queries are forwarded and returned as response packets, malformed queries are dropped, and upstream I/O errors propagate to the caller.

The policy engine, packet processor, codec, UDP forwarder, and packet-to-packet engine are pure JVM components. The forwarder opens a real UDP socket when called, but no Android service currently supplies VpnService.protect or routes device queries into it. None of these components reads from a TUN interface or enforces traffic policy on a device. EDNS support follows the OPT wire format in [RFC 6891, section 6.1.2](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.2). The parser accepts only EDNS version 0 and rejects malformed option lengths.

## Current limits

- The packet-to-packet engine can process a supplied IPv4 UDP DNS packet and return a response packet, but it does not read from or write to a TUN descriptor. The UDP forwarder can send allowed queries to a configured resolver when called with a working socket-protection callback. No Android service currently wires these components together.
- It does not load or update the production tracker database.
- It does not identify which app made a query.
- It rejects compressed question names, multiple questions, answer/authority records, more than one additional record, non-OPT additional records, non-IN question classes, non-ASCII hostnames, and EDNS versions other than 0.
- It does not filter DNS-over-HTTPS, DNS-over-TLS, or DNS-over-QUIC.
- It has not been tested on a physical Android device.

The next integration stage still needs a real Android VpnService, a TUN read/write loop, a VpnService.protect-backed socket callback, UDP/TCP DNS handling (including TCP fallback), IPv6 strategy, cancellation and network-change handling, and emulator/device tests. The current forwarder is UDP-only and validates response identity/question, not every answer-record structure. RFC 7766 requires general-purpose DNS implementations to support both UDP and TCP, so TCP DNS must not be silently treated as covered by this UDP codec.

## Run tests

Requires JDK 17 and network access for Gradle dependencies:

    gradle test

The repository CI workflow also runs the tests. Do not treat the code as CI-verified until a workflow run is observed and passes.
