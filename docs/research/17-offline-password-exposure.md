# 17 — Offline password exposure lookup

**Research status:** official HIBP Pwned Passwords range-response documentation and downloader source checked 19 November 2026.  
**Implementation status:** partial Kotlin/JVM range-file matcher on open PR #26. A directory-format mismatch was corrected in this follow-up; exact-head CI is pending. No device validation or performance measurement is claimed. PR #26 remains unmerged. Android UI, dataset import and authenticated provenance are not implemented.

## Scope decision

Have I Been Pwned documents two different data products:

- **Account breach search:** searches breach records associated with an email address. The direct account endpoint requires an API key. The email hash-range k-anonymity endpoint is subscription-gated through the account's IncludesKAnon capability.
- **Pwned Passwords:** a separate corpus of previously exposed password hashes. It is available without an API subscription and can be downloaded for offline use. The published corpus contains SHA-1 and NTLM password hashes, not email addresses or account-to-breach records. This core uses the SHA-1 variant over UTF-8 input (S59, S60).

Therefore PrivaCage must not call the first local implementation an offline email/account breach lookup. The buildable first slice is a password-exposure check against the official Pwned Passwords corpus. It does not identify which account was breached, the source breach, or whether a password is otherwise strong.

## Official directory format

The official downloader supports a directory containing one range file per five-character uppercase SHA-1 prefix. The file is named PREFIX.txt; each non-empty line is the raw API response record: a 35-character uppercase SHA-1 suffix, a colon, and a positive occurrence count. The five-character prefix is represented by the filename and is not repeated in each directory-mode record. The official API documents 35-character SHA-1 suffixes and CRLF line endings (S64). The downloader's single-file mode differs: it prepends the prefix to each suffix to produce full 40-character hashes, so that output must not be used as a PREFIX.txt range file.

The upstream source pinned in S61 defines `RangeCount = 1024 * 1024` and iterates every prefix from `00000` through `FFFFF`. In directory mode it writes each API response body unchanged to a temporary file, verifies that body against the API's `Content-MD5` header, and only then replaces the corresponding `PREFIX.txt`. It does not prepend the five-character prefix to directory-mode records. Single-file mode separately prepends the prefix while merging suffix records. A successful directory download therefore processes all 1,048,576 prefix requests, subject to the operator trusting the official downloader and its HTTPS connection. The downloader writes the response body even when it is empty; the current PrivaCage matcher intentionally treats a zero-byte range as unavailable until an importer can distinguish a verified empty range from a missing or truncated file.

The optional `sha1.index` is a prefix-sorted list of ETag values used for conditional refresh. A response without an ETag still writes its range file but is removed from the index and downloaded again on a later run. Therefore `sha1.index` is not a complete inventory and must never be used to prove that every prefix is present. `Content-MD5` is a transfer-integrity check, not a publisher signature; the downloader does not publish a signed completeness manifest, and the ETag index does not authenticate a copied directory (S61). Reviewed 19 November 2026.

## Implemented core on PR #26

PwnedPasswordRangeLookup.checkAndClear:

1. Takes ownership of a dedicated CharArray and clears it on every exit path.
2. Encodes the supplied characters as UTF-8 and calculates SHA-1 solely for compatibility with the HIBP corpus.
3. Opens only the matching PREFIX.txt file through a read-only channel with symbolic-link following disabled; the byte size is captured from that opened handle.
4. Reads no more than the captured size, enforces a 4 MiB file cap and 100,000-line cap, and rejects records longer than the 55-byte `suffix:count` format bound before allocating a decoded line. It validates exactly 35 uppercase hexadecimal suffix characters, strict suffix ordering and positive canonical counts; the five-character prefix is selected by the range filename.
5. Returns FOUND with the corpus count or NOT_FOUND_IN_SNAPSHOT with the caller-supplied snapshot date.

Android API compatibility was checked 17 November 2026: the app's minSdk is 26, and Android documents both Files.newByteChannel and LinkOption.NOFOLLOW_LINKS from API 26. Android also documents that NOFOLLOW_LINKS may be ignored by providers that do not support symbolic links; no physical-device provider validation is claimed (S62, S63).

A missing, empty, unreadable, symbolic-link, truncated, malformed, oversized or unsorted range throws an explicit error. It is never converted into a no-match result. The opened handle prevents a path swap to a symbolic link after validation; the captured-size read ignores later appends and fails if the file is truncated before the captured bytes are read. Intermediate password byte arrays are cleared. The core has no networking dependency, does not persist the raw password and does not read the HIBP ETag index.

## Import design decision

The next safe implementation is a desktop-side, bounded directory verifier/importer rather than a full-corpus copy into Android app-private storage. It should require all 1,048,576 expected `PREFIX.txt` names, reject symlinks and unexpected path types, validate every range with bounded parsing, and compute a SHA-256 digest and record/byte counts for each prefix. A compact manifest can bind the range inventory, per-range digests, total counts/bytes, claimed snapshot date, and downloader/importer versions.

No HIBP publisher-signed manifest is published by the official downloader. A manifest signed by a user-controlled Ed25519 key would authenticate that user's local import attestation and detect later file changes only after the public-key fingerprint is trusted out of band; it would not prove HIBP publisher authenticity or independently authenticate the claimed snapshot date. Keep those claims separate in the UI and docs. Android access should be evaluated through a user-selected Storage Access Framework location, without assuming the entire corpus can be copied into app-private storage. The manifest format and Android provider lifecycle are not implemented yet.

## Security and accuracy limits

- SHA-1 is used only as the identifier required by the published corpus. It is not used to store, protect or authenticate passwords.
- The caller supplies the snapshot date. The current core does not authenticate that date, verify a signed manifest, validate the entire dataset's completeness, or prove freshness.
- The matcher validates the one range file it needs. A valid no-match means only that the password hash was absent from that supplied range file. A syntactically valid but truncated file cannot yet be detected; until an import/manifest path authenticates range digests and coverage, a no-match is only a local-file observation, not an authoritative corpus result.
- A no-match is not proof that the password is strong, unique, safe, or absent from every breach.
- The corpus contains password hashes, not email/account breach records. No email address or identifier is sent.
- Android UI, secure text-field lifecycle, Storage Access Framework import, dataset-size planning, provenance manifest and device-level memory review remain unfinished.
- PrivaCage does not bundle or redistribute the corpus. Users must obtain it from the official source and maintain it themselves.

## Next acceptance gates

- Implement the desktop verifier first; require all 1,048,576 prefix files and validate the full bounded directory before creating a manifest.
- Define a compact manifest with per-range SHA-256 digests, record/byte counts, a claimed snapshot date, and downloader/importer versions. Sign it with a user-controlled key and require separate out-of-band public-key fingerprint confirmation on any consumer device. Describe this as a local import attestation, not a HIBP publisher signature.
- Test the importer against interrupted downloads, missing prefixes, unexpected files, empty ranges, malformed records, and post-import file tampering. A missing or digest-mismatched range must remain unavailable, never a no-match.
- Evaluate Android Storage Access Framework access to a user-selected external dataset location; do not copy a potentially very large full corpus into app-private storage without measured device/storage evidence.
- Add an Android UI only after secure text-field lifecycle, dataset storage, manifest verification, and provider behavior are tested on representative devices.
- Keep account/email breach search separate. Do not send full identifiers to a third-party endpoint, scrape the service, or imply that the Pwned Passwords corpus can answer account-breach questions.

This is engineering guidance, not a guarantee of account security or a legal/technical audit of the upstream dataset.
