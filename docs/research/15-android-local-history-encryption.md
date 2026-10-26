# 15 — Android Local DNS History Encryption

**Status:** Implemented in the Android codebase. On commit `ee4e7c617da4745016d8ec94ddef5bfe47c71170`, the Android privacy-suite tests and shared-data validation passed, and the full Android app/DNS workflow passed both Rust JNI builds, debug APK packaging, DNS core tests, app unit tests, Go privacy baseline validation, and inspection of the bundled tracker and app-alternative catalogs. See [privacy-suite CI](https://github.com/VireonNoctis/PrivaCage/actions/runs/40308297192) and [full Android build CI](https://github.com/VireonNoctis/PrivaCage/actions/runs/40308297064). The emulator performance comparison was still running when this note was updated. Physical-device Keystore lifecycle testing remains outstanding.

## Purpose and threat boundary

DNS hostnames can reveal searches, services, health interests, work systems, or routines. PrivaCage's optional history stores the queried hostname, DNS decision, timestamp, and a best-effort socket-owner label. The history is off by default, local-only, capped at 100 events, and retained for 1, 7, or 30 days (7 days by default).

The purpose of encryption at rest is to reduce exposure if the preferences file is copied or read outside the running application under a threat model where Android Keystore still protects the key. This is not a universal protection against a compromised/rooted OS, a compromised PrivaCage process after decryption, runtime memory inspection, or a user exporting an audit file. Exported JSON remains plaintext by design and must be reviewed before sharing.

Platform reference: [S09b — Android Keystore](SOURCES.md#s09b), [S09c — SharedPreferences.Editor](SOURCES.md#s09c), and [S09d — SharedPreferences storage guidance](SOURCES.md#s09d).

## Implemented design

- The event list is encrypted with `AES/GCM/NoPadding`. The versioned JSON envelope contains only `version`, a Base64 IV, and Base64 ciphertext.
- The generated IV is 12 bytes. The GCM authentication tag is 128 bits. A fixed, version-specific additional-authenticated-data string binds the ciphertext to this envelope purpose; malformed envelopes, unexpected fields, unsupported versions, invalid lengths, wrong keys, and authentication failures are rejected.
- The AES-256 key is generated and used through the `AndroidKeyStore` provider with encryption/decryption purposes and randomized encryption enabled. The key is not written into the preferences file. Hardware-backed key storage is not guaranteed on every device.
- The canonical plaintext size ceiling is 256 KiB of serialized UTF-8. The event count remains capped at 100. Retention is applied on app launch, recording, history refresh, and export; there is no background worker whose only purpose is deleting history.
- Normal writes target the encrypted preference key. The old `dns_event_history_json` key is retained only as a migration source for existing installations.

The cryptographic envelope is isolated in `LocalDnsHistoryCipher.kt`, making the AES-GCM format testable on a host JVM without pretending a host JVM can emulate Android Keystore behavior.

## Upgrade and failure handling

1. **Encrypted record exists.** The app loads the existing Keystore key and authenticates/decrypts the envelope. If the key is missing or authentication fails, it does not create a replacement key, declare the history empty, or fall back to the old plaintext key.
2. **Legacy plaintext exists and no encrypted record exists.** The app obtains or creates the history key, encrypts the existing value, synchronously confirms the encrypted copy was stored, then removes the legacy plaintext preference. If the second removal cannot be confirmed, both copies are preserved and the next access retries removal.
3. **Neither key exists.** Reads use an empty history without creating an unnecessary encryption key. A key is created only when a record must be stored.
4. **Saved records, timestamps, or the envelope are malformed.** The app stops pruning and stops recording into that history rather than partially discarding records. Export fails instead of silently omitting the unreadable records. The user can explicitly clear the history through the UI.
5. **Legacy plaintext exceeds the supported 256 KiB encryption limit.** Migration cannot encrypt that oversized value; it is preserved rather than discarded and the history view reports an error. This is an abnormal/corrupted-storage edge case, not a supported valid history. The user can explicitly clear the old history if recovery is not possible.
6. **Clear history.** The encrypted and legacy preference keys are removed in one preference edit. The Keystore key itself is not deleted; it contains no event content and can be reused for future history after the user re-enables recording.

The encrypted copy is committed before the legacy plaintext value is removed because migration must not destroy the only copy of the user's existing evidence. `SharedPreferences` editor writes are synchronous here to obtain an explicit success result; the history operations are executed on background threads rather than the UI thread. Android's API guidance also warns that `commit()` can block and that `apply()` cannot report disk-write failures.

## Test coverage and outstanding verification

The host-JVM `LocalDnsHistoryCipherTest` covers round-trip encryption, hostname non-disclosure in the serialized envelope, wrong-key rejection, ciphertext tampering, unsupported versions, unexpected fields, invalid IV length, and oversized plaintext. The Android privacy-suite workflow also runs the DNS core and app unit tests. These tests exercise the format and Kotlin integration at compile/unit-test level; they do not prove real-device Keystore lifecycle behavior.

Before release, verify the following on supported Android API levels and at least one physical device from each relevant OEM family:

- Upgrade from an installation that has legacy plaintext DNS history; confirm a correct history view after migration and no legacy value after successful migration.
- Force-stop or reboot during migration; confirm the old data or encrypted data remains recoverable and that no path silently reports an empty history.
- Delete or invalidate the Keystore alias in a dedicated test build/device; confirm encrypted data remains untouched and new key generation is refused while an encrypted record exists.
- Flip stored ciphertext bytes or alter the IV; confirm authentication fails, no retention pruning happens, and export reports failure.
- Run with history disabled, enable it, record allowed and blocked requests, change retention, clear the history, and re-enable; confirm the preferences contain ciphertext rather than raw hostnames.
- Measure DNS response latency while history is enabled, because each recorded event currently serializes and re-encrypts the bounded list.
- Check the exact OS/version behavior for key availability before first unlock and after device credential/security changes.

## Maintenance decisions

The existing implementation keeps a bounded list in the established app-private preferences store. This is a focused patch, not a claim that SharedPreferences is the ideal persistence engine for a growing event database. If the history grows beyond the present small bound or needs transactional queries, evaluate Room/DataStore and keep the encryption/migration contract explicit. Never silently auto-delete history merely because decryption fails; deletion remains a user-visible operation.
