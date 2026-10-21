# PrivaCage Android DNS policy core

This is the first isolated Kotlin implementation slice for Android DNS filtering. It is a JVM library, not an Android application or VPN service.

## What it does

- Parses a deliberately restricted form of classic DNS query message.
- Normalizes configured domain rules to lowercase.
- Matches an exact domain or a true subdomain suffix (for example, `ads.example.org` matches `example.org`, while `notexample.org` does not).
- Returns an explicit allow, block, or malformed result.
- Rejects unsupported input rather than silently treating malformed messages as allowed.

## What it does not do

- It does not capture device traffic, open sockets, forward DNS queries, synthesize DNS responses, create a VPN tunnel, or block packets.
- It does not load or update a production tracker database.
- It does not identify which app made a query.
- It does not support DNS compression in the question name, EDNS additional records, multiple questions, non-IN classes, or non-ASCII IDNs in this initial parser.
- It does not filter DNS-over-HTTPS, DNS-over-TLS, or DNS-over-QUIC.
- It has not yet been tested on a physical Android device.

The current parser rejects EDNS additional records, which are common in modern DNS traffic. That limitation must be addressed before integrating this policy core into a usable DNS transport.

## Run tests

Requires JDK 17 and network access for Gradle dependencies:

    gradle test

The repository CI workflow also runs the tests. Until a workflow run is observed and passes, do not treat the code as CI-verified.
