# PrivaCage Terms of Service

**Version:** 0.1-draft  
**Prepared:** 3 November 2026  
**Status:** Draft — the controller identity, contact details, governing law and effective date must be completed before publication.

> **Important:** This document is not a substitute for legal review. It is not ready to be used as a final consumer contract while the bracketed details remain unresolved.

## 1. Provider

PrivaCage is an open-source privacy-auditing companion project.

The provider for this release is intended to be:

- **Provider / contracting entity:** [CONTROLLER LEGAL NAME / ENTITY]
- **Privacy and legal contact:** [PRIVACY CONTACT EMAIL]
- **Postal address:** [POSTAL ADDRESS]
- **Effective date:** [EFFECTIVE DATE]

The source repository and the software licence do not, by themselves, identify the legal person or entity responsible for a particular hosted deployment. A self-hosted relay or web backend is operated by the person or organisation that deploys it.

## 2. Scope

These terms apply to the PrivaCage Android application and project-operated services only to the extent the provider actually operates them. The separate Windows command-line tools and static web workspace have platform-specific capabilities and limitations. An iOS application is not represented as shipped or complete by this Android release.

Third-party resolvers, app stores, browsers, operating systems, and user-hosted relay servers are not operated by PrivaCage merely because the app can connect to them.

## 3. Local-first operation

PrivaCage is designed to keep privacy-audit information on the device by default. It does not require a PrivaCage user account and does not have a central account profile containing a user's name, email address, telephone number, contacts, or identity documents.

Some features intentionally make network requests when the user uses them. Examples include forwarding DNS queries to a configured resolver and synchronising encrypted packets with a relay that the user configures. These are described in the Privacy Policy and External Services document.

## 4. User control and permissions

You are responsible for:
- using the app only on devices and networks you own or are authorised to administer;
- reviewing permissions and special Android access before granting them;
- selecting and reviewing any DNS resolver and sync relay;
- safeguarding device unlock credentials, recovery passphrases and exported files; and
- retaining any independent evidence you need for a legal or privacy request.

The app will not silently revoke another app's permissions or claim that a permission audit proves what an app actually did.

## 5. No telemetry and no advertising

The Android client is developed under a strict no-product-telemetry policy. It does not intentionally include advertising identifiers, product analytics, session replay, behavioural profiling, or remote crash-reporting SDKs. It does not silently upload local audit records to the project.

This does not disable Android, device-manufacturer, carrier, network-provider, DNS-resolver, browser, app-store, or third-party service diagnostics. It also does not prevent a feature from making the user-directed network requests described in the Privacy Policy. See the Strict No-Telemetry Policy.

## 6. Privacy and security tools

Privacy reports are based on the sources and operating-system interfaces available to the relevant tool. Static APK indicators, manifest permissions, DNS names, and permission-grant snapshots do not prove that an app transmitted a particular item of data.

The Android DNS feature is a DNS-only path, not a full-device VPN or guarantee that all traffic is filtered. DNS-over-TLS is optional. A selected DNS resolver can still see the query names it resolves.

Some local files and preferences are encrypted with Android Keystore-backed AES-GCM keys. Encrypted storage does not protect data while it is being used in process memory, from a compromised operating system, from a rooted device, or from someone who has unlocked access to the device. Exported audit checkpoint JSON is signed but not encrypted by default. See Data Retention and Encryption.

## 7. Open-source licence

The repository's applicable open-source licence continues to govern copying, modification, distribution and use of the source code. These terms do not replace or silently alter the MIT licence or any third-party component licence. Where a licence grants a right that cannot lawfully be restricted by these terms, that right remains unaffected.

## 8. No legal or security guarantee

PrivaCage is a privacy-assistance tool, not a guarantee of anonymity, complete traffic visibility, complete removal of metadata, universal tracker blocking, legal compliance by another organisation, or deletion of data from another organisation.

No tool can establish that a third party has erased all copies of data without reliable evidence from that party or an independent audit. Users should preserve original evidence and seek qualified legal or security advice for high-risk situations.

## 9. Availability, changes and termination

Features may change as operating systems and supported devices change. A feature may be disabled where it no longer meets its documented security boundary. Material changes to these terms should be versioned and made available before they take effect where the law requires.

Users can stop using the app and remove local data by using the app's available clear/delete controls or uninstalling/clearing app data. External providers and relay operators have separate deletion processes and retention policies.

## 10. Mandatory rights and liability

Nothing in these terms excludes or limits a consumer right, statutory protection, or liability that cannot lawfully be excluded or limited. Any limitation of liability, warranty disclaimer, or governing-law clause must be completed and reviewed for the actual provider and countries where the app is offered. No broad waiver of mandatory consumer rights is intended by this draft.

## 11. Governing law and disputes

**Governing law:** [INSERT AFTER LEGAL REVIEW]  
**Competent courts / dispute process:** [INSERT AFTER LEGAL REVIEW]

Mandatory consumer-protection and data-protection rights remain unaffected.

## 12. Contact

For questions about these terms, contact [PRIVACY CONTACT EMAIL]. Replace this placeholder with a real monitored address before publication.
