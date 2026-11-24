# Pwned Passwords local manifest-attestation vector v1

This fixture is a cross-language verification vector for the PrivaCage local manifest-attestation format.

- `attestation.json` contains a P-256 ECDSA/SHA-256 signature over the exact SHA-256 digest in the shared four-prefix manifest fixture.
- `trusted-public-key-sha256.txt` is the out-of-band trust-anchor value used by tests.
- The private test key was generated only to produce this fixture and is not included.

The signature authenticates possession of the corresponding test key for this exact manifest digest. It does not authenticate Have I Been Pwned, prove source completeness/freshness, or establish a trusted timestamp. The four-prefix manifest is a test fixture, not a production dataset.
