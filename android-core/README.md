# PrivaCage Android DNS policy core

This is an isolated Kotlin/JVM policy library, not an Android application or VPN service.

## What it does

- Parses a restricted subset of classic DNS queries with exactly one question.
- Validates a single EDNS(0) OPT pseudo-record, including the record's fixed fields and each option's declared length.
- Treats unknown EDNS option payloads as opaque, as required for forward compatibility; it does not interpret or rewrite them.
- Normalizes configured domain rules and matches exact domains or true subdomain suffixes.
- Returns an explicit allow, block, or malformed result.

EDNS support follows the OPT wire format in [RFC 6891, section 6.1.2](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.2). The parser accepts only EDNS version 0 and rejects malformed option lengths.

## Current limits

- This component does not capture device traffic, open sockets, forward DNS queries, synthesize DNS responses, create a VPN tunnel, or block packets.
- It does not load or update the production tracker database.
- It does not identify which app made a query.
- It rejects compressed question names, multiple questions, answer/authority records, more than one additional record, non-OPT additional records, non-IN question classes, non-ASCII hostnames, and EDNS versions other than 0.
- It does not filter DNS-over-HTTPS, DNS-over-TLS, or DNS-over-QUIC.
- It has not been tested on a physical Android device.

Supporting EDNS removes one major parser limitation, but this is not enough to safely integrate a packet tunnel. A transport still needs bounded packet framing, UDP/TCP DNS forwarding behavior, valid block responses, cancellation and network-change handling, and device/emulator tests.

## Run tests

Requires JDK 17 and network access for Gradle dependencies:

    gradle test

The repository CI workflow also runs the tests. Do not treat the code as CI-verified until a workflow run is observed and passes.
