# Privacy research notes

**Reviewed:** 2026-10-21  
**Purpose:** Record the evidence behind product opportunities and OS constraints. These notes are not a claim that PrivaCage already implements the listed protections.

## 1. Sensitive location data can expose intimate patterns

The US Federal Trade Commission's January 2024 action against X-Mode Social/Outlogic addressed alleged sale and sharing of sensitive location data. The FTC described how location trails can reveal visits to medical facilities, places of worship, and domestic-abuse shelters. This is a concrete basis for treating location-data exposure as a serious privacy concern, not merely an advertising annoyance.

**Product opportunities**
- A local permission and location-access history where the OS provides the data.
- An explanation of how precise location can be inferred from repeated observations.
- A location-data broker opt-out/request tracker with submission evidence and no claim of guaranteed removal.
- A share-before-send metadata inspector for photos and documents.

**Limits:** a companion app cannot reconstruct every data broker's datasets or prove that a company has stopped selling a user's data.

Source: https://www.ftc.gov/news-events/news/press-releases/2024/01/ftc-order-prohibits-x-mode-social-and-outlogic-selling-sensitive-location-data

## 2. Android VPN-based filtering is useful but exclusive and user-controlled

Android's official VPN documentation says only one VPN service can be active per user/profile; starting another stops the existing one. The VpnService API also requires user consent for initial setup and provides a system-managed notification while the VPN runs.

**Product opportunities**
- Explain clearly that enabling PrivaCage may replace a user's existing VPN.
- Add a preflight screen showing the active VPN state and warning about the conflict before activation.
- Test tunnel interruption, network changes, IPv6, DNS fallback, and safe recovery.
- Keep rule decisions and diagnostic events local.

**Limits:** a local VPN is not a kernel-level system-call monitor. It cannot inspect arbitrary HTTPS payloads and does not guarantee visibility into every OEM/system-service connection.

Sources:
- https://developer.android.com/develop/connectivity/vpn
- https://developer.android.com/reference/android/net/VpnService

## 3. Apple offers several network-extension mechanisms, each with specific entitlements

Apple's official Network Extensions documentation lists separate capabilities for DNS proxying, content filtering, packet tunnels, and related networking functions. The available mechanism depends on the app's configured entitlement and distribution constraints.

**Product opportunities**
- Treat iOS network filtering as a separate feasibility track, not a promise to clone Android behavior.
- Build an entitlement/provisioning validation checklist before committing to an implementation.
- Provide an honest companion experience if the required entitlement or deployment model is unavailable.

**Limits:** listing an API in documentation does not guarantee that every app can obtain every entitlement or use every mode in every distribution context. Validate the exact capability and deployment path.

Sources:
- https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.networking.networkextension
- https://developer.apple.com/documentation/NetworkExtension/packet-tunnel-provider

## 4. VPN disclosure and consent are product requirements, not optional polish

Google Play's VpnService policy requires qualifying use of VpnService to be declared and includes prominent disclosure and consent requirements when sensitive user data is accessed or collected.

**Product opportunities**
- Write the in-app disclosure before building the packet engine.
- Document what metadata is inspected, what is logged, what is never collected, and whether any data leaves the device.
- Make local filtering rules inspectable and exportable.
- Avoid analytics SDKs and remote logging in the privacy tool itself.

Source: https://support.google.com/googleplay/android-developer/answer/12564964

## 5. Prioritized feature candidates

| Candidate | User concern | Feasibility | Honest limitation |
|---|---|---|---|
| DNS block + rule audit | Ads, trackers, unwanted connections | Buildable on Android using VpnService | Only traffic and protocols visible to the implementation can be filtered |
| Photo/document metadata scrubber | Accidental GPS and author metadata disclosure | Buildable with format-specific local processing | Each format needs its own tests; metadata removal cannot erase content visible in the file itself |
| Permission drift reminders | Apps retain access longer than expected | Depends on OS-exposed permission state | Native settings may be the only place to change another app's permission |
| Privacy-change comparison | Updates add SDKs or permissions | Buildable for user-selected Android APKs | Static signatures are not proof of runtime collection |
| Broker request tracker | Users want access/deletion/opt-out help | Buildable as a local workflow | Submission is not proof of deletion or removal from downstream copies |
| DNS/VPN status diagnostics | Users cannot tell whether protection is active | Buildable incrementally | A diagnostic is not proof of every service's network path |
| IoT inventory and traffic baseline | Smart devices may contact unexpected services | Requires router/resolver data or an explicitly authorized LAN scan | A phone-only VPN cannot observe every device on the LAN |
| Offline breach lookup | Users want to check exposure without disclosing identifiers | Feasible with a curated local dataset | Coverage can be incomplete and stale |
| Stalkerware safety signals | Concern about covert monitoring | Research first; use only observable, documented indicators | Signals are not proof; changing settings can increase risk in coercive situations |
| Fingerprinting education | Cookies are not the only tracking mechanism | Education and browser-specific guidance are feasible | A companion app cannot force arbitrary browsers to randomize rendering fingerprints |

## Research hygiene

- Prefer official OS documentation, regulators, peer-reviewed research, and reproducible technical analysis.
- Record publication/review dates for changing APIs and laws.
- Separate a source's factual claim from our interpretation and proposed feature.
- Re-check sources before shipping legal templates or platform-specific enforcement.
- Do not infer that a feature is technically possible just because users want it.
