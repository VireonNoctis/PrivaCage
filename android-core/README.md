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

The packet codec is a pure JVM component. It does not read from a TUN interface, forward allowed DNS queries, start an Android service, or enforce traffic policy. EDNS support follows the OPT wire format in [RFC 6891, section 6.1.2](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.2). The parser accepts only EDNS version 0 and rejects malformed option lengths.

## Current limits

- Neither component captures device traffic, opens sockets, forwards allowed DNS queries, creates a VPN tunnel, or blocks packets. The packet codec can synthesize a DNS REFUSED response, but no service currently sends it to a device.
- It does not load or update the production tracker database.
- It does not identify which app made a query.
- It rejects compressed question names, multiple questions, answer/authority records, more than one additional record, non-OPT additional records, non-IN question classes, non-ASCII hostnames, and EDNS versions other than 0.
- It does not filter DNS-over-HTTPS, DNS-over-TLS, or DNS-over-QUIC.
- It has not been tested on a physical Android device.

The next integration stage still needs a real Android VpnService, a TUN read/write loop, protected upstream resolver sockets, forwarding of allowed queries, UDP and TCP DNS behavior, IPv6 strategy, cancellation and network-change handling, and emulator/device tests. RFC 7766 requires general-purpose DNS implementations to support both UDP and TCP, so TCP DNS must not be silently treated as covered by this UDP codec.

## Run tests

Requires JDK 17 and network access for Gradle dependencies:

    gradle test

The repository CI workflow also runs the tests. Do not treat the code as CI-verified until a workflow run is observed and passes.
