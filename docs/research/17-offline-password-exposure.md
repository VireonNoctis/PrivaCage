# 17 — Offline password exposure lookup

**Research status:** official HIBP Pwned Passwords range-response documentation and downloader source checked 19 November 2026; Android MessageDigest and Storage Access Framework APIs checked 21 November 2026; ContentResolver, ContentProvider, AssetFileDescriptor and CancellationSignal APIs checked 23 November 2026.  
**Implementation status:** partial Kotlin/JVM matcher, Go full-range inventory verifier, Kotlin full-manifest/selected-range verifier, one-shot Android SAF stream-snapshot adapter, and experimental Android check screen on open PR #26. The code-bearing PR head af419f7 passed all nine workflows on 23 November 2026; the performance benchmark step was skipped because emulator acceleration was unavailable. Physical-device/DocumentProvider validation remains outstanding. The manifest remains unsigned and requires an independently retained SHA-256. Physical-device/DocumentProvider validation remains outstanding. The screen does not persist URI grants; signed local attestation, publisher-authenticated provenance, and account/email lookup remain unimplemented.

## Scope decision

Have I Been Pwned documents two different data products:

- **Account breach search:** searches breach records associated with an email address. The direct account endpoint requires an API key. The email hash-range k-anonymity endpoint is subscription-gated through the account's IncludesKAnon capability.
- **Pwned Passwords:** a separate corpus of previously exposed password hashes. It is available without an API subscription and can be downloaded for offline use. The published corpus contains SHA-1 and NTLM password hashes, not email addresses or account-to-breach records. This core uses the SHA-1 variant over UTF-8 input (S59, S60).

Therefore PrivaCage must not call the first local implementation an offline email/account breach lookup. The buildable first slice is a password-exposure check against the official Pwned Passwords corpus. It does not identify which account was breached, the source breach, or whether a password is otherwise strong.

## Official directory format

The official downloader supports a directory containing one range file per five-character uppercase SHA-1 prefix. The file is named PREFIX.txt; each non-empty line is the raw API response record: a 35-character uppercase SHA-1 suffix, a colon, and a positive occurrence count. The five-character prefix is represented by the filename and is not repeated in each directory-mode record. The official API documents 35-character SHA-1 suffixes and CRLF line endings (S64). The official API describes the occurrence count but does not specify a maximum numeric width; PrivaCage deliberately bounds it to a positive canonical unsigned 64-bit value for a shared Kotlin/Go contract. Values above that local limit fail closed and are not claimed to be accepted by HIBP. The downloader's single-file mode differs: it prepends the prefix to each suffix to produce full 40-character hashes, so that output must not be used as a PREFIX.txt range file.

The upstream source pinned in S61 defines `RangeCount = 1024 * 1024` and iterates every prefix from `00000` through `FFFFF`. In directory mode it writes each API response body unchanged to a temporary file, verifies that body against the API's `Content-MD5` header, and only then replaces the corresponding `PREFIX.txt`. It does not prepend the five-character prefix to directory-mode records. Single-file mode separately prepends the prefix while merging suffix records. A successful directory download therefore processes all 1,048,576 prefix requests, subject to the operator trusting the official downloader and its HTTPS connection. The downloader writes the response body even when it is empty. The legacy single-range matcher treats an empty file as unavailable. The manifest-backed path permits a zero-byte range only when the full manifest digest and selected empty-range SHA-256/zero-record entry both verify.

The optional `sha1.index` is a prefix-sorted list of ETag values used for conditional refresh. A response without an ETag still writes its range file but is removed from the index and downloaded again on a later run. Therefore `sha1.index` is not a complete inventory and must never be used to prove that every prefix is present. `Content-MD5` is a transfer-integrity check, not a publisher signature; the downloader does not publish a signed completeness manifest, and the ETag index does not authenticate a copied directory (S61). Reviewed 19 November 2026.

## Implemented core on PR #26

PwnedPasswordRangeLookup.checkAndClear:

1. Takes ownership of a dedicated CharArray and clears it on every exit path.
2. Encodes the supplied characters as UTF-8 and calculates SHA-1 solely for compatibility with the HIBP corpus.
3. Opens only the matching PREFIX.txt file through a read-only channel with symbolic-link following disabled; the byte size is captured from that opened handle.
4. Reads no more than the captured size, enforces a 4 MiB file cap and 100,000-line cap, and rejects records longer than the 56-byte `suffix:count` format bound before allocating a decoded line. It validates exactly 35 uppercase hexadecimal suffix characters, strict suffix ordering and positive canonical unsigned 64-bit counts; Kotlin uses `ULong` and Go uses `uint64` so both implementations accept the same 56-byte maximum record. The five-character prefix is selected by the range filename.
5. Returns FOUND with the corpus count or NOT_FOUND_IN_SNAPSHOT with the caller-supplied snapshot date.

Android API compatibility was checked 17 November 2026: the app's minSdk is 26, and Android documents both Files.newByteChannel and LinkOption.NOFOLLOW_LINKS from API 26. Android also documents that NOFOLLOW_LINKS may be ignored by providers that do not support symbolic links; no physical-device provider validation is claimed (S62, S63). The SHA-256 digest API is available from API level 1 (S67).

A missing, empty, unreadable, symbolic-link, truncated, malformed, oversized or unsorted range throws an explicit error. It is never converted into a no-match result. The opened handle prevents a path swap to a symbolic link after validation; the captured-size read ignores later appends and fails if the file is truncated before the captured bytes are read. Intermediate password byte arrays are cleared. The core has no networking dependency, does not persist the raw password and does not read the HIBP ETag index.

## Desktop full-range inventory verifier

The shared Go CLI now provides `create-pwned-manifest` and `verify-pwned-manifest` on PR #26. Creation requires all 1,048,576 uppercase `PREFIX.txt` files, permits only an optional regular `sha1.index`, rejects unexpected entries and symbolic links, and validates each range before recording it. Each range is bounded to 4 MiB and 100,000 records; the total dataset is bounded to 256 GiB. Records must contain a 35-character uppercase hexadecimal suffix, a positive canonical unsigned 64-bit decimal count (matching Kotlin `ULong`), and strictly increasing suffixes. CRLF, LF, and a final record without a newline are accepted. Empty files are recorded as zero-byte/zero-record ranges; an all-empty directory is rejected.

The output is JSON Lines: one header with the source label, format version, operator-supplied snapshot date, generation timestamp and aggregate counts, followed by one ordered entry per prefix containing byte size, record count and SHA-256. The manifest is limited to 128 MiB. The verifier requires an independently retained SHA-256 digest, then checks the manifest structure, complete prefix inventory and every current range-file digest. Before parsing, it copies exactly the captured size from the opened manifest handle into a temporary snapshot while computing SHA-256; only the digest-matched snapshot is parsed. This prevents a same-size in-place rewrite between a separate digest pass and the parse pass, and a truncation or digest mismatch aborts before range-directory scanning. Removal of the temporary snapshot is attempted on every exit path; cleanup failures are returned rather than silently ignored. It makes no network requests and does not read or rely on `sha1.index`.

Commands:

```sh
go -C shared/go/pcage-tools run . create-pwned-manifest \
  --directory /path/to/pwned-passwords \
  --manifest /path/out/ranges.jsonl \
  --snapshot-date YYYY-MM-DD

go -C shared/go/pcage-tools run . verify-pwned-manifest \
  --directory /path/to/pwned-passwords \
  --manifest /path/out/ranges.jsonl \
  --expected-sha256 DIGEST_RETAINED_SEPARATELY
```

The digest must be stored separately from the manifest and dataset. This is an unsigned local inventory; it detects accidental or later byte changes only when the expected digest remains trusted. It is not a signed attestation. Run creation against a quiescent directory. The creator checks file metadata while reading and re-enumerates the directory, but it is not a filesystem snapshot and cannot defend against a privileged concurrent writer that can restore timestamps. Run the verification command after creation to confirm that the current directory still matches the generated manifest.

## Kotlin manifest consumer on PR #26

The Kotlin verifier consumes the Go JSONL format without loading the full manifest into memory. It caps the manifest at 128 MiB and each JSONL record at 4 KiB, rejects non-ASCII input, duplicate or unknown JSON fields, non-canonical numeric values, future snapshot dates, invalid timestamps, missing/out-of-order prefixes, inconsistent aggregate totals, and trailing or unterminated data. It requires exactly the configured prefix count (1,048,576 in the production default) and compares the SHA-256 of the exact manifest bytes with a separately retained expected digest using MessageDigest.isEqual.

After the manifest is validated, the matcher opens only the password's selected PREFIX.txt range with symbolic-link following disabled. It checks the selected file's size, parses and orders every bounded record, counts records, and computes SHA-256 while reading that same open channel. A match or snapshot-scoped no-match is returned only when the selected range's byte digest and record count match the manifest entry. A zero-byte range is therefore usable only when the independently digest-bound manifest declares zero bytes/records and the empty-file SHA-256 matches. Missing, changed, malformed, or truncated selected ranges remain unavailable.

The shared fixture under shared/crypto/test-vectors/pwned-password-manifest/v1 is consumed by Go and Kotlin tests. It exercises CRLF range data, an empty range, a maximum-format count record, manifest digest binding, and a selected-prefix lookup. The four-prefix fixture is a test vector only; production verification defaults to the full 1,048,576-prefix inventory.

This verifies the manifest bytes relative to a separately retained digest and the selected range relative to its manifest entry. It does not authenticate HIBP, prove that the original upstream response was complete, or verify every range file on Android during one password lookup. The snapshot date remains an operator claim. The verifier uses local filesystem Paths; the separate SAF adapter snapshots the user-selected manifest and range into that path-based verifier, but provider/device behavior remains unvalidated.

## Signed attestation and Android import design

A signature is deliberately deferred until a reviewed key-custody flow exists. The Go/Kotlin manifest-format test vector is present, but a user-controlled signature would authenticate only that user's local attestation, not HIBP as publisher or the truth of the claimed snapshot date. Do not label the current JSONL manifest as signed.

The Android SAF adapter accepts a user-selected manifest document URI and one selected uppercase PREFIX.txt URI through ContentResolver. It copies only the manifest (128 MiB maximum) and selected range (4 MiB maximum) into a short-lived app-private cache snapshot, then delegates to the existing digest-bound verifier/matcher. It does not enumerate the flat 1,048,576-file directory, copy the full corpus, or persist URI grants. The caller uses the active read grant from ACTION_OPEN_DOCUMENT; reselect after the Activity/process ends. A third-party provider may fetch remote bytes itself, so choose a local/offline copy when offline operation is required. Missing display names, revoked grants, null streams, read failures, oversized streams, a mismatched prefix, and digest/record-count failures remain unavailable/errors, never a no-match. The experimental Android screen is present; persistent-grant lifecycle, physical-device/provider validation, and signed local attestation remain future work. The Activity passes a per-check CancellationSignal to the ContentResolver display-name query and openAssetFileDescriptor request. Providers that honor it can stop their own query/open or provider-side stream work, but a provider that ignores cancellation or an already-blocked client-side read may still delay cleanup.

## Security and accuracy limits

- SHA-1 is used only as the identifier required by the published corpus. It is not used to store, protect or authenticate passwords.
- The caller supplies the snapshot date. The Go manifest records that claim but is unsigned; the independent SHA-256 is only a trust anchor if retained separately. Neither the Kotlin matcher nor the Go verifier authenticates HIBP as publisher or proves source completeness/freshness.
- The Kotlin matcher validates only the one range file it needs. The Go tool validates the full filename inventory and record syntax, then binds the observed files with per-range SHA-256 values. A syntactically valid truncation at a record boundary can still be included in a locally generated manifest; the tool cannot prove that the upstream response was complete. A no-match is not an authoritative corpus result until the manifest digest is independently trusted and consumed by the Android matcher.
- A no-match is not proof that the password is strong, unique, safe, or absent from every breach.
- The corpus contains password hashes, not email/account breach records. No email address or identifier is sent.
- The experimental Android UI and one-shot SAF import are present on PR #26. Persistent URI-grant lifecycle, physical-device/DocumentProvider validation, signed local attestation, publisher-authenticated provenance and device-level memory review remain unfinished.
- PrivaCage does not bundle or redistribute the corpus. Users must obtain it from the official source and maintain it themselves.

## Next acceptance gates

- Add a signed local attestation only after selecting a key-custody design and adding a Kotlin verifier with shared Go/Kotlin test vectors. Keep the expected public-key fingerprint out of band; describe the signature as a local import attestation, not a HIBP publisher signature.
- Validate the existing Android UI around the one-shot SAF adapter on representative devices and providers. Keep the password field lifecycle short, clear its editable buffer after submission, and run verification off the main thread. The Activity interrupts its worker and passes a per-check Android CancellationSignal to ContentResolver metadata queries and openAssetFileDescriptor requests on explicit cancellation or loss of foreground focus. Providers may ignore the signal, and an already-blocked client-side read may still delay cleanup. Add persistent URI grants only if the UI needs reuse across activity/process restarts; persist only the read grant explicitly returned for the selected document, and test revocation.
- Test the importer against interrupted downloads, missing prefixes, unexpected files, empty ranges, malformed records, and post-import file tampering. A missing or digest-mismatched range must remain unavailable, never a no-match.
- Validate the stream-snapshot adapter against representative local and cloud-backed document providers, including revocation, null streams, partial reads, large manifests, and cleanup after cancellation. The provider may itself use the network; PrivaCage does not claim to control that provider behavior.
- Complete physical-device and DocumentProvider validation of the existing UI, including secure text-field lifecycle, manifest verification, provider revocation and cancellation cleanup.
- Keep account/email breach search separate. Do not send full identifiers to a third-party endpoint, scrape the service, or imply that the Pwned Passwords corpus can answer account-breach questions.

This is engineering guidance, not a guarantee of account security or a legal/technical audit of the upstream dataset.


## Android user flow (22 November 2026)

The main screen exposes an experimental password-exposure check. It opens the system ACTION_OPEN_DOCUMENT picker twice: once for the JSONL manifest and once for a single uppercase PREFIX.txt range. The user enters a 64-character manifest SHA-256 retained separately and the password to check. The Activity does not call takePersistableUriPermission, does not save selected URI grants, and does not request storage permissions. It copies only the selected manifest and range through ContentResolver into bounded app-private cache and removes the snapshot when the operation closes.

The password editor is not saved in view state or offered to Android autofill. Its contents are copied character-by-character into a dedicated CharArray, the editor is cleared before work, and the matcher clears the array on every exit path. The editor is also cleared when the Activity pauses. If the Activity loses foreground focus, it interrupts the worker and cancels the per-check Android CancellationSignal; explicit cancellation uses the same path. The signal is passed to the ContentResolver metadata query and openAssetFileDescriptor request. Providers that honor it can stop their own query/open or stream-generation work, but a provider that ignores it or an already-blocked client-side read may still delay cleanup. This does not guarantee zeroization of an Android keyboard/input method's own buffers. The full manifest verification and selected-range lookup run on a worker thread.

The screen reports FOUND with the corpus occurrence count or NOT_FOUND_IN_SNAPSHOT with the manifest-declared date. It never calls a no-match safe, never reports account/email breach status, and does not test password strength. A cloud-backed document provider can observe file reads, but PrivaCage sends it no password or upload. The expected digest does not authenticate HIBP or establish source completeness/freshness.
