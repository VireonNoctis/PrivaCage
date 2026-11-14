# 17 — Offline password exposure lookup

**Research status:** official HIBP API, Pwned Passwords page and downloader source checked 14 November 2026.  
**Implementation status:** partial Kotlin/JVM range-file matcher on PR #26; not merged. Android UI, dataset import and authenticated provenance are not implemented.

## Scope decision

Have I Been Pwned documents two different data products:

- **Account breach search:** searches breach records associated with an email address. The direct account endpoint requires an API key. The email hash-range k-anonymity endpoint is subscription-gated through the account's IncludesKAnon capability.
- **Pwned Passwords:** a separate corpus of previously exposed password hashes. It is available without an API subscription and can be downloaded for offline use. The published corpus contains SHA-1 and NTLM password hashes, not email addresses or account-to-breach records. This core uses the SHA-1 variant over UTF-8 input (S59, S60).

Therefore PrivaCage must not call the first local implementation an offline email/account breach lookup. The buildable first slice is a password-exposure check against the official Pwned Passwords corpus. It does not identify which account was breached, the source breach, or whether a password is otherwise strong.

## Official directory format

The official downloader supports a directory containing one range file per five-character uppercase SHA-1 prefix. The file is named PREFIX.txt; each non-empty line is the full 40-character uppercase SHA-1 hash, a colon, and a positive occurrence count. The downloader writes the prefix before the API suffix when producing directory files. It also creates an optional sha1.index of prefix/ETag pairs for conditional refresh. That index is an update optimization, not proof that all ranges are present.

The downloader verifies each HTTP range against the API's Content-MD5 response header before accepting it and atomically replaces individual range files. This verifies the downloaded response at that time; it is not a signed dataset manifest and does not authenticate a later copied directory (S61).

## Implemented core on PR #26

PwnedPasswordRangeLookup.checkAndClear:

1. Takes ownership of a dedicated CharArray and clears it on every exit path.
2. Encodes the supplied characters as UTF-8 and calculates SHA-1 solely for compatibility with the HIBP corpus.
3. Opens only the matching PREFIX.txt file in a caller-supplied local directory.
4. Enforces a 4 MiB file cap and 100,000-line cap; validates full uppercase SHA-1 values, prefix membership, strict ordering and positive canonical counts.
5. Returns FOUND with the corpus count or NOT_FOUND_IN_SNAPSHOT with the caller-supplied snapshot date.

A missing, empty, unreadable, malformed, oversized or unsorted range throws an explicit error. It is never converted into a no-match result. Intermediate byte arrays are cleared. The core has no networking dependency, does not persist the raw password and does not read the HIBP ETag index.

## Security and accuracy limits

- SHA-1 is used only as the identifier required by the published corpus. It is not used to store, protect or authenticate passwords.
- The caller supplies the snapshot date. The current core does not authenticate that date, verify a signed manifest, validate the entire dataset's completeness, or prove freshness.
- The matcher validates the one range file it needs. A valid no-match means only that the password hash was absent from that supplied range file. A syntactically valid but truncated file cannot yet be detected; until an import/manifest path authenticates range digests and coverage, a no-match is only a local-file observation, not an authoritative corpus result.
- A no-match is not proof that the password is strong, unique, safe, or absent from every breach.
- The corpus contains password hashes, not email/account breach records. No email address or identifier is sent.
- Android UI, secure text-field lifecycle, Storage Access Framework import, dataset-size planning, provenance manifest and device-level memory review remain unfinished.
- PrivaCage does not bundle or redistribute the corpus. Users must obtain it from the official source and maintain it themselves.

## Next acceptance gates

- Define a bounded import/manifest format with explicit source, hash algorithm, snapshot date, downloader version and locally computed digests; clearly distinguish local integrity checks from publisher authenticity.
- Verify missing-range behavior and snapshot staleness before presenting any negative result.
- Add an Android UI only after a secure input lifecycle and realistic storage/import approach are tested on representative devices.
- Keep account/email breach search separate. Do not send full identifiers to a third-party endpoint, scrape the service, or imply that the Pwned Passwords corpus can answer account-breach questions.

This is engineering guidance, not a guarantee of account security or a legal/technical audit of the upstream dataset.
