package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pwnedAttestationVector(t *testing.T) (attestation []byte, fingerprint string, manifestPath string) {
	t.Helper()
	root := filepath.Join("..", "..", "crypto", "test-vectors", "pwned-password-attestation", "v1")
	var err error
	attestation, err = os.ReadFile(filepath.Join(root, "attestation.json"))
	if err != nil {
		t.Fatalf("read shared attestation vector: %v", err)
	}
	fingerprintBytes, err := os.ReadFile(filepath.Join(root, "trusted-public-key-sha256.txt"))
	if err != nil {
		t.Fatalf("read shared trust-anchor vector: %v", err)
	}
	fingerprint = strings.TrimSpace(string(fingerprintBytes))
	manifestPath = filepath.Join("..", "..", "crypto", "test-vectors", "pwned-password-manifest", "v1", "manifest.jsonl")
	return attestation, fingerprint, manifestPath
}

func TestPwnedManifestAttestationSharedKotlinVector(t *testing.T) {
	attestation, fingerprint, manifestPath := pwnedAttestationVector(t)
	manifestDigest, signerFingerprint, err := verifyPwnedManifestAttestation(attestation, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	actualDigest, err := hashPwnedManifestForAttestation(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifestDigest != actualDigest {
		t.Fatalf("attested digest %s does not match shared manifest %s", manifestDigest, actualDigest)
	}
	if signerFingerprint != fingerprint {
		t.Fatalf("signer fingerprint %s does not match trust anchor %s", signerFingerprint, fingerprint)
	}
}

func TestPwnedManifestAttestationRejectsWrongTrustAnchor(t *testing.T) {
	attestation, _, _ := pwnedAttestationVector(t)
	if _, _, err := verifyPwnedManifestAttestation(attestation, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong independently trusted fingerprint must be rejected")
	}
}

func TestPwnedManifestAttestationRejectsTamperingAndMalformedJSON(t *testing.T) {
	attestation, fingerprint, _ := pwnedAttestationVector(t)
	original := string(attestation)
	tampered := strings.Replace(original, "BB5A8AA3754FD3A62A59C679441858269D2534D94129826F78FA26FFC6FACD91", strings.Repeat("A", 64), 1)
	if tampered == original {
		t.Fatal("shared vector manifest digest was not found")
	}
	if _, _, err := verifyPwnedManifestAttestation([]byte(tampered), fingerprint); err == nil {
		t.Fatal("tampered manifest digest must invalidate the signature")
	}

	duplicate := strings.Replace(original, "\"version\": 1", "\"version\": 1,\"version\": 1", 1)
	if _, _, err := verifyPwnedManifestAttestation([]byte(duplicate), fingerprint); err == nil {
		t.Fatal("duplicate JSON keys must be rejected")
	}
	unknown := strings.Replace(original, "{", "{\"unexpected\":true,", 1)
	if _, _, err := verifyPwnedManifestAttestation([]byte(unknown), fingerprint); err == nil {
		t.Fatal("unknown JSON fields must be rejected")
	}
}

func TestPwnedManifestAttestationRejectsNonCanonicalOrOversizedInput(t *testing.T) {
	attestation, fingerprint, _ := pwnedAttestationVector(t)
	nonCanonical := strings.Replace(string(attestation), "\"version\": 1", "\"version\": 1.0", 1)
	if _, _, err := verifyPwnedManifestAttestation([]byte(nonCanonical), fingerprint); err == nil {
		t.Fatal("non-integer attestation version must be rejected")
	}
	if _, _, err := verifyPwnedManifestAttestation(make([]byte, pwnedAttestationFileLimit+1), fingerprint); err == nil {
		t.Fatal("oversized attestation must be rejected")
	}
}
