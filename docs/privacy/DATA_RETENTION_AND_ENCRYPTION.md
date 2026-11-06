# Data Retention and Encryption

**Version:** 0.1-draft  
**Prepared:** 3 November 2026

This document describes the current Android implementation. It does not claim that every operational preference, system log, exported file or third-party service record is encrypted by PrivaCage.

## 1. Local Android data

| Data | What is stored | Protection / retention |
|---|---|---|
| DNS configuration | Resolver IPv4 address, blocked-domain rules, DNS-over-TLS flag and TLS hostname | AES-256-GCM encrypted app-private preference using its own Android Keystore key. Persists until replaced, cleared or app data is removed. Legacy plaintext settings are migrated after validation and a confirmed commit. |
| Rights-request tracker | Jurisdiction, right, controller name entered by the user, dates, planning deadlines and status | AES-256-GCM encrypted app-private preference with a separate Keystore key. At most 100 records and 512 KiB. Persists until user deletes records, clears the tracker, or removes app data. Draft text, user's name/email, identity documents and submission receipts are not stored in this tracker. |
| Permission-audit comparison baseline | Launcher-visible package names, dangerous permission names, grant booleans and capture timestamp | AES-256-GCM encrypted app-private preference with a separate Keystore key. At most 2,000 packages, 256 permissions per package and 4 MiB. Replaced only after a complete successful scan; user can clear it. |
| Optional DNS history | Domain, timestamp, allow/block decision and best-effort socket-owner label | Off by default. When enabled, AES-GCM encrypted using Android Keystore. Up to 100 events. User-selected retention is 1, 7 or 30 days (default 7 days); user can clear it. Exported reports are plaintext if the user chooses to export them. |
| App-policy review queue | Launcher-visible package names, install/open trigger timestamps and user-entered policy URLs | AES-256-GCM encrypted local file with a separate Keystore key. Up to 100 pending apps. App-open observations require Usage Access and inspect at most the recent 24-hour window; Android retains events for only a few days. Items remain until marked reviewed or the package disappears from the visible inventory; reviewed-package suppression remains while the app remains installed. App data removal deletes local history. |
| Sync identity and local relay configuration | Device identity bundle, local recovery metadata, relay/capability settings, roster state and cursors | Encrypted at rest in an Android Keystore-protected AES-GCM envelope. The identity bundle itself uses its own recovery/passphrase protection. |
| Other operational preferences | Aggregate DNS counters, history-enabled/retention flags, lifecycle status and diagnostic UI state | App-private preferences. These are not uploaded by PrivaCage, but the current implementation does not encrypt every non-secret operational value with a dedicated AES-GCM envelope. |

## 2. Exported files and temporary files

- .pcage DNS profiles are encrypted before being written, using Argon2id and AES-256-GCM.
- The signed audit checkpoint format is plaintext JSON with integrity/authenticity checks. It is not encrypted by default and can contain hostnames or socket-owner labels if the user selects those fields for export.
- User-selected APK and media inspections stage bounded temporary copies in private app cache. Those temporary copies are deleted after the inspection or cancellation path. Deletion is not a guarantee of physical overwriting of flash storage.
- Files the user saves or shares through Android's document provider or another app are outside PrivaCage's retention control. The receiving app, file provider, cloud backup or recipient may retain them.

## 3. Optional sync relay retention and metadata

The current relay implementation:
- stores encrypted packet bytes, message IDs, space IDs, cursors, expiry/insert timestamps and public roster/device-card information;
- stores SHA-256 hashes of space/member capabilities rather than raw tokens;
- stores signed member-request nonces for five minutes to prevent replay;
- does not decrypt packet contents;
- expires message rows after seven days and nonce rows after five minutes;
- prunes expired rows at startup and every 60 seconds, as well as during message access;
- enables SQLite `secure_delete=ON` for ordinary table deletions; and
- limits each space to 10,000 non-expired packets.

The application does not persist source IP addresses or log request headers/bodies. It necessarily sees request-authentication metadata in memory, including member fingerprint, timestamp, nonce, signature, space/message IDs and payload size. A reverse proxy or hosting provider can see source IP and other connection metadata and may retain paths, headers, body sizes or request timing according to its own configuration. SQLite deletion/secure-delete is not a promise of physical erasure: WAL frames, file-system snapshots, volume backups and copied database files remain deployment-level retention risks. The repository relay defaults to loopback; a public relay is operated by whoever deploys it.

## 4. Third-party retention

A DNS resolver may retain DNS queries and connection metadata. A public relay host/reverse proxy may retain connection logs. External browser destinations and app stores apply their own policies. PrivaCage cannot delete those records unless the relevant operator provides and honours a deletion mechanism.

## 5. Key loss and recovery

If an Android Keystore key used to protect an existing encrypted record disappears or cannot be used, the app must fail closed and preserve the ciphertext. It must not silently create a replacement key and claim that the previous data is recoverable. The user may need an independent encrypted export or an explicit app-data reset, which can destroy unrecoverable local data.

AES-GCM protects stored bytes from unauthorised reading and detects tampering. It does not protect plaintext in memory, visible screens, unlocked-device access, a compromised OS, a rooted device, or malicious code running inside the app process.

## 6. Retention review

A release owner must re-check this document whenever record counts, expiry intervals, encryption formats, export fields, app backup settings or relay storage rules change. The project should not invent an expiry period for a dataset that the code currently retains until user deletion.
