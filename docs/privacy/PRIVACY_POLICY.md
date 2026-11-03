# PrivaCage Privacy Policy

**Version:** 0.1-draft  
**Prepared:** 3 November 2026  
**Status:** Draft — not release-ready until the controller, contact details, lawful bases, actual service operators and effective date are completed and reviewed.

> **Controller information is currently incomplete.** The repository does not establish the legal name, address or privacy contact of the person/entity that will be the controller for a released distribution. Those details must be filled in; they must not be inferred from a GitHub username.

## 1. Who is responsible?

- **Controller:** [CONTROLLER LEGAL NAME / ENTITY]
- **Privacy contact:** [PRIVACY CONTACT EMAIL]
- **Postal address:** [POSTAL ADDRESS]
- **Data Protection Officer:** [CONFIRM WHETHER APPOINTMENT IS REQUIRED; ADD CONTACT IF APPOINTED]
- **Effective date:** [EFFECTIVE DATE]

A person who independently hosts a PrivaCage relay, website, reverse proxy or other service may be a separate controller or processor depending on the actual purposes and arrangements. That operator must publish its own accurate notice where required.

## 2. Core promise

PrivaCage is designed to operate locally by default. The Android app does not require a PrivaCage account. The project does not intentionally collect a user's name, email address, telephone number, contacts, advertising ID, location history or identity documents through an account system.

The Android client has no product analytics, advertising, session-replay or remote crash-reporting SDK. It does not silently upload local privacy reports, app inventories, permission snapshots, DNS history, rights-request metadata, API credentials or sync private keys to a PrivaCage analytics service.

This is not a claim that the whole device or all network activity is invisible. Android, device manufacturers, mobile operators, Wi-Fi/network operators and the external services the user selects may process their own data. Some app features intentionally send specific requests to destinations chosen or confirmed by the user.

## 3. Information kept on the device

The current Android implementation can store the following information locally:

- **DNS configuration:** a numeric resolver address, blocked-domain rules, and whether DNS-over-TLS is enabled plus its certificate hostname. This configuration is encrypted in an app-private AES-256-GCM envelope using an Android Keystore key.
- **Optional DNS history:** when the user enables it, a bounded history can contain domain names, timestamps, allow/block decisions and best-effort socket-owner labels. Recording is off by default. The history is encrypted at rest.
- **Permission-audit baseline:** launcher-visible package identifiers, dangerous permission names and boolean grant states, with a device-clock capture timestamp. The comparison baseline is encrypted at rest. This is not a complete device inventory and does not record actual sensor use.
- **App policy review queue:** launcher-visible package identifiers, observed install/open trigger and timestamps, plus policy URLs entered by the user. This queue is encrypted at rest. App-open observation requires the user's separate Android Usage Access grant.
- **Rights-request tracker:** jurisdiction, the right being tracked, controller name entered by the user, preparation/receipt/deadline dates and a user-managed status. The draft request text, user's name/email, identity documents and submission receipts are not stored by this tracker. Its metadata store is encrypted at rest.
- **AI provider credentials:** a user-supplied API token, selected model, purpose note and permitted task list. Tokens are encrypted at rest and are not included in PrivaCage sync or Android backup. A token must be present in app memory and sent to the selected provider when the user makes a request.
- **Encrypted sync identity:** local identity keys and relay configuration are held in an Android Keystore-protected encrypted record. The protocol's device private keys are not uploaded in readable form.
- **Other operational preferences:** aggregate DNS counters, feature toggles, lifecycle status and diagnostic UI state may be stored in app-private preferences. These are not uploaded by PrivaCage, but not every operational preference is currently covered by the dedicated AES-GCM stores.

The app manifest disables Android Auto Backup. This source setting is checked by CI, but behaviour can vary across Android versions, OEM migration mechanisms and device-transfer tools.

## 4. Information sent outside the device

PrivaCage does not treat all network traffic as telemetry. The following feature requests are functional traffic, not product analytics:

### 4.1 DNS resolver

When the user starts DNS filtering, the supported DNS queries are forwarded to the configured resolver. The resolver can see the queried domain names and the user's network source address as observed by that resolver. If DNS-over-TLS is enabled, the connection between PrivaCage and that resolver is encrypted and the certificate hostname is verified; the resolver still sees the DNS query. If DNS-over-TLS is disabled, the upstream DNS request is not encrypted by this app.

The app's DNS route is limited to supported DNS traffic addressed to its virtual endpoints. It does not cover every app-owned DoH/DoQ request, arbitrary tunnel, direct-IP connection, or general device packet. The resolver is selected/configured by the user and is not automatically operated by PrivaCage.

### 4.2 AI provider

If the user saves a supported provider API token, selects an allowed task, pastes text and confirms a request, PrivaCage sends that text to the chosen provider's fixed HTTPS API endpoint. The provider receives the submitted text, API credential/authentication information and ordinary network connection metadata such as the source IP address.

No installed-app inventory, DNS history, rights tracker, files or other device state is attached automatically. The provider applies its own privacy notice, terms, retention, account and billing rules. The user should not paste information they are not authorised to share.

### 4.3 Optional encrypted sync relay

If the user configures and uses a relay, the Android client sends signed, recipient-encrypted packets to that relay. The relay stores opaque packet bytes and does not decrypt the payload.

The relay can still see operational metadata, including space ID, message ID, timestamps/cursors, payload length, public device cards/fingerprints and access patterns. The relay's SQLite schema stores a hash of a capability token, not the token itself. Packet records expire after seven days under the current relay implementation. A reverse proxy or hosting provider may separately retain connection metadata such as source IP, time, request path and user-agent depending on its configuration.

The repository relay defaults to loopback. It is not a central PrivaCage account service. A public relay is independently deployed and operated by whoever configures it.

### 4.4 External links and distribution

When the user opens a policy link, official source, app store or other external website, the destination and the browser/OS receive the ordinary information needed to make that connection. Those destinations are not controlled by PrivaCage.

### 4.5 Web workspace

The repository web workspace is a static catalogue console and a separate Rust/Axum API. The API binds to loopback by default and serves the embedded tracker catalogue and derived catalogue summaries/capabilities. It is not connected to an Android device or a live telemetry stream. If someone publicly deploys it, that operator's host, reverse proxy and network infrastructure may process connection logs under their own configuration.

## 5. Telemetry, analytics and advertising

The Android application is governed by the Strict No-Telemetry Policy. No product analytics, ad tracking, session replay, cross-app tracking identifier or remote crash-reporting SDK is intentionally included. No local privacy-audit data is sent to the project merely because the app starts or a user opens a screen.

CI scans the Android manifest, Gradle files and application source for known analytics, advertising and crash-reporting SDK markers. This is a regression control, not mathematical proof that every possible hand-written telemetry implementation or OS/OEM data path is absent.

## 6. Purposes and legal bases

The feature purposes are described above: local privacy auditing, user-configured DNS filtering, local app-policy reminders, local rights-request tracking, user-requested AI text analysis, and user-configured encrypted sync.

**The controller must complete this section before publication.** The exact Article 6 GDPR lawful basis (and, if applicable, any Article 9 condition) must be determined for each operation based on who controls the released service and what processing actually occurs. Do not assume that every optional feature relies on consent or that a local-only operation necessarily creates a controller relationship with the project maintainer.

## 7. Recipients and international transfers

PrivaCage does not sell personal data or share it with data brokers. The app does not have an advertising partner or an analytics vendor.

Recipients may include only the external destination selected for a feature:
- the DNS resolver configured by the user;
- the AI provider selected by the user;
- the relay host configured by the user;
- an external browser, app store or source website opened by the user; and
- the host/reverse-proxy operator of any public web or relay deployment.

Those operators may be located outside the EEA. The relevant operator must explain its own international-transfer mechanism, safeguards and retention. PrivaCage cannot promise the practices of a third-party provider or self-hosted service.

## 8. Retention and deletion

Local records remain on the device until their feature-specific deletion, expiry or replacement rule runs, or the user clears/uninstalls the app. See Data Retention and Encryption for the detailed limits and exceptions.

PrivaCage cannot delete a DNS provider's query logs, AI provider's request records, an external website's access logs, or relay-host logs on the user's behalf. Users must use the relevant operator's own controls or contact that operator.

## 9. Security

Selected local records use AES-256-GCM encryption with Android Keystore-held keys. Some export formats use Argon2id and AES-256-GCM. The sync protocol encrypts packets for recipients and signs device messages.

Encryption does not protect data while it is in application memory, while it is displayed, from a compromised/rooted operating system, from malware with access to the app process, or from a person using an unlocked device. Android Keystore hardware backing differs by device. A lost Keystore key can make existing ciphertext unreadable; the app deliberately does not replace a missing key and pretend the old data was recovered.

Some signed audit checkpoint exports are plaintext JSON. Exporting them is an explicit user action and the exported file may contain hostnames or socket-owner labels chosen for inclusion. The user controls the destination and subsequent sharing.

## 10. Your rights

Where GDPR or another data-protection law applies, individuals may have rights including access, rectification, erasure, restriction, objection, portability, withdrawal of consent where consent is the basis, and the right to complain to a supervisory authority. These rights are subject to the conditions and exceptions in the applicable law.

Local-only data can generally be inspected, cleared or deleted by the user on their device. Where a controller holds personal data outside the device, the controller must provide a working route for rights requests. The final contact route must be inserted above before release.

Irish Data Protection Commission: https://www.dataprotection.ie/

## 11. Legal disclosures

PrivaCage does not voluntarily disclose user information to authorities. If the responsible operator receives a binding legal demand, it will assess the request, its jurisdiction and scope, challenge or narrow it where legally available, and disclose only the minimum information that is lawfully required and actually held or controlled. Notification will be provided where lawful and safe to do so.

The exact data that could be available is set out in the Authority and Legal-Request Policy. That policy does not promise immunity from lawful process or control over third-party service providers.

## 12. Changes

A material change to collection, purpose, recipients, retention, telemetry, local encryption or legal-disclosure practice requires an updated policy version and appropriate notice before the new processing begins where required by law.
