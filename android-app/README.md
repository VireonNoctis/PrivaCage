# PrivaCage Android app adapter

This is the first Android platform adapter for the pure Kotlin/JVM DNS core in `../android-core`.

## Implemented

- Local UI for a numeric IPv4 upstream resolver and user-entered blocked domains.
- Local-only settings in Android SharedPreferences.
- Explicit `VpnService.prepare()` consent.
- A `VpnService` with a virtual DNS address and a route only to that address.
- A blocking TUN read/write loop that processes supported IPv4 UDP DNS packets and returns responses.
- A protected upstream UDP socket using `VpnService.protect(DatagramSocket)`.
- A foreground notification and explicit handling of tunnel I/O/processing errors.

## Build

Requires JDK 17, Android SDK platform 36, and Gradle 8.14 or compatible.

    gradle assembleDebug
    gradle :android-core:test

The debug APK is generated at `app/build/outputs/apk/debug/app-debug.apk`.

## Limits

- Only user-entered domains are blocked; no verified tracker list is bundled or loaded.
- Only IPv4 UDP DNS is supported. TCP DNS, IPv6 DNS, DoH, DoT, and DoQ are not filtered.
- Upstream DNS uses ordinary UDP to the user-selected resolver, not encrypted DNS.
- Truncated UDP responses are not retried over TCP; large answers may fail.
- Queries are processed sequentially; a slow resolver delays later requests.
- The service does not attribute queries to apps or inspect HTTPS contents.
- This code has not been built in this environment or tested on an emulator/device. CI and device validation are required before calling it release-ready.
- Platform/device policy can prevent VPN or foreground-service startup. Failures stop the service; DNS query names are not logged.
