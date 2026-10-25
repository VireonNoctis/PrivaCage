# 06 — Identifiers, Browser Fingerprinting and Shared-File Metadata

**Research status:** platform and regulator source review, 25 October 2026  
**Decision this note supports:** prioritize controls PrivaCage can actually deliver at the device/share boundary.

## 1. Identifiers are not interchangeable

| Identifier/signal | Main risk | Practical user control | What the control does not guarantee |
|---|---|---|---|
| Advertising ID | App ecosystem ad measurement/profiling and cross-app association | Use current OS ad privacy/reset controls and review app permissions | Does not erase server-side history, account identifiers, IP-based correlation or fingerprints |
| App-scoped random ID | Persistent identity inside one app/service | Clear app data, reset account/device session if supported | May not reset server account records or other linked identifiers |
| Account/user ID | Join events to a signed-in account | Account privacy settings, opt-out/deletion request, avoid optional sign-in | App may retain records under legal exceptions/retention rules |
| IP address/network metadata | Coarse location/network/device association and behavioral inference | Network configuration, privacy settings, local network policy | IP can change but does not eliminate account and fingerprint signals |
| Browser fingerprint | Identify or re-identify from browser/device characteristics | Use a browser that reduces fingerprinting, limit extension sprawl, avoid unusual configuration | No universal OS switch makes all websites see a stable anonymous identity |
| Photo/document metadata | Reveal GPS, device, author, software, creation/modification details | Strip metadata from a derivative copy before sharing | Does not remove content visible inside the image/document or metadata added after upload |

Android's privacy checklist recommends resettable identifiers, states that ordinary apps targeting Android 10/API 29 or higher receive a `SecurityException` when attempting to access persistent identifiers like IMEI/serial, and describes advertising ID expectations ([S06](SOURCES.md#s06)). Android 13+ apps that target API 33+ must account for the `AD_ID` permission in Play services; if the required permission is absent, the advertising ID can be returned as zeroes ([S07](SOURCES.md#s07)). UI wording must match current OS behavior, not promise that every app has access to every identifier.

## 2. Browser fingerprinting

A fingerprint is formed by combining browser/device characteristics into a distinguishable profile; examples include browser version, available fonts and rendering behavior. Modern browsers deploy mitigations such as restricting information or adding variation/noise ([S28](SOURCES.md#s28)). Fingerprinting may persist when cookies are cleared, but it is not infallible and its uniqueness depends on the user population and signals available.

### What PrivaCage can do

- Provide a browser privacy checklist and compare documented privacy features/version settings.
- Recommend an established browser/hardened profile rather than pretending a companion app can modify all browsers.
- If PrivaCage develops its own browser, consider privacy-preserving defaults such as reducing high-entropy APIs, consistent per-site behavior, isolated storage and clear permission prompts. Test compatibility and fingerprintability against reproducible test suites before claiming improvement.
- For an in-app WebView controlled by PrivaCage, set secure defaults for that WebView only and document that third-party apps' independent WebViews are outside its control.

### What not to ship as a false promise

An Android VPN cannot randomize canvas output, installed font enumeration or JavaScript API outputs. A randomizer injected into every app/browser is not available to a normal app. Root/Xposed hooks might alter some process behavior but are brittle, hard to validate and can increase risk. Treat system-wide fingerprint randomization as outside stock scope.

## 3. Advertising ID rotation reminders

A practical feature is a contextual reminder explaining where the current OS exposes advertising/privacy controls and what resetting or deleting the identifier means. The reminder must be version-aware and user-triggered. Do not promise to silently reset the ID for all apps. Do not access identifiers merely to prove they exist; use platform-provided documentation and user-facing settings flow where possible.

An event record could store only:

- `action`: `opened_settings`, `user_confirmed_reset`, or `not_verified`;
- `timestamp`, OS version and source of confirmation;
- no raw advertising identifier unless there is a compelling, user-approved, tested need—which the MVP does not have.

The user's tap on a settings link is not proof a setting changed. If the platform does not let PrivaCage verify the new state, say so.

## 4. EXIF and document metadata scrubber

This is a strong practical feature because it acts on a file the user explicitly selected, rather than claiming to control other apps. Image and document formats can contain structured metadata in addition to visible pixels/text. Photo workflows should preserve the original and export a cleaned copy.

### Functional requirements

- Use Android/iOS share sheets and file pickers so the user explicitly chooses the input.
- Process on-device by default. Do not upload the file for cleaning.
- Inventory metadata categories before removal: GPS, camera/device make/model, timestamps, author/software, embedded thumbnails, XMP/IPTC and relevant format-specific fields.
- Offer a transparent preview: “GPS coordinates present,” “camera model present,” “author field present,” not a frightening score.
- Save to a new output file; never overwrite the original without explicit intent.
- Verify the exported file by parsing it again. If any target field remains or the format cannot be processed reliably, show a clear partial-failure report.
- Keep visible pixels/document content unchanged unless the user explicitly chooses re-encoding. Record re-encoding effects such as changed quality, color profile or file size.
- For PDF, office files, HEIC/HEIF, JPEG, PNG and other formats, define separate supported-format behavior. Do not advertise universal metadata removal from an image library that handles only JPEG EXIF.
- Remove or regenerate embedded thumbnails and sidecar metadata where relevant; a file can leak data in more than one metadata container.

### Acceptance tests

Create test fixtures for files with GPS, camera model, date/time, author, XMP/IPTC, embedded thumbnail and orientation data. After cleaning, verify the fields are absent while orientation and color remain visually correct. Include malformed files, unsupported formats, very large files, encrypted documents, and failed writes. The UI must state which format and field categories were actually verified.

## 5. Shared files are a high-leverage privacy seam

The user often cannot control what a receiving platform does with content after upload, but can control the metadata in a local copy before sharing. This feature has a narrow, understandable trust boundary: user-selected file in, cleaned copy out. It can be integrated into Android share-sheet handling and iOS document/photo share flows without inventing a universal sensor detector.

## 6. Breach exposure checker — later, with privacy protection

A breach checker can itself leak an email address to the service being queried. Prefer offline matching against an explicitly downloaded and integrity-verified corpus where licensing and freshness permit, or a well-documented k-anonymity/range-query protocol if using a remote service. Never send a full email address or password to a breach API by default. Do not request, store or test passwords. Report breach membership as historical exposure information, not proof an account is currently compromised.

## 7. Acceptance criteria

- No raw device/ad identifier is stored for a reminder feature.
- Reset actions are reported as confirmed only where the OS exposes verifiable state.
- Metadata cleaning works on a copy and re-parses its output.
- Unsupported formats and partial scrubs are visible as failures, not “cleaned successfully.”
- Fingerprinting advice states its scope and does not imply VPN-layer control over browser APIs.