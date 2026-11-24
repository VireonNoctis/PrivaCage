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


func pwnedBundleFixture(t *testing.T) (directory, manifestPath, attestationPath, fingerprint string) {
	t.Helper()
	attestation, fingerprint, sourceManifest := pwnedAttestationVector(t)
	sourceRoot := filepath.Dir(sourceManifest)
	root := t.TempDir()
	directory = filepath.Join(root, "ranges")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatalf("create range fixture directory: %v", err)
	}
	for _, prefix := range []string{"00000", "00001", "00002", "00003"} {
		data, err := os.ReadFile(filepath.Join(sourceRoot, "ranges", prefix+".txt"))
		if err != nil {
			t.Fatalf("read range fixture %s: %v", prefix, err)
		}
		if err := os.WriteFile(filepath.Join(directory, prefix+".txt"), data, 0600); err != nil {
			t.Fatalf("write range fixture %s: %v", prefix, err)
		}
	}
	manifest, err := os.ReadFile(sourceManifest)
	if err != nil {
		t.Fatalf("read manifest fixture: %v", err)
	}
	manifestPath = filepath.Join(root, "manifest.jsonl")
	if err := os.WriteFile(manifestPath, manifest, 0600); err != nil {
		t.Fatalf("write manifest fixture: %v", err)
	}
	attestationPath = filepath.Join(root, "attestation.json")
	if err := os.WriteFile(attestationPath, attestation, 0600); err != nil {
		t.Fatalf("write attestation fixture: %v", err)
	}
	return directory, manifestPath, attestationPath, fingerprint
}

func TestPwnedBundleVerifierValidatesSignatureManifestAndEveryRange(t *testing.T) {
	directory, manifestPath, attestationPath, fingerprint := pwnedBundleFixture(t)
	header, signerFingerprint, err := verifyPwnedBundle(directory, manifestPath, attestationPath, fingerprint, 4)
	if err != nil {
		t.Fatalf("verify signed four-range fixture: %v", err)
	}
	if header.RangeCount != 4 || header.TotalRecords == 0 || header.TotalBytes == 0 {
		t.Fatalf("unexpected verified manifest totals: %+v", header)
	}
	if signerFingerprint != fingerprint {
		t.Fatalf("verified signer %s does not match trusted fingerprint %s", signerFingerprint, fingerprint)
	}
}

func TestPwnedBundleVerifierRejectsWrongTrustAnchor(t *testing.T) {
	directory, manifestPath, attestationPath, _ := pwnedBundleFixture(t)
	if _, _, err := verifyPwnedBundle(directory, manifestPath, attestationPath, strings.Repeat("0", 64), 4); err == nil {
		t.Fatal("wrong trust anchor must reject the bundle")
	}
}

func TestPwnedBundleVerifierRejectsModifiedManifest(t *testing.T) {
	directory, manifestPath, attestationPath, fingerprint := pwnedBundleFixture(t)
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(manifest, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyPwnedBundle(directory, manifestPath, attestationPath, fingerprint, 4); err == nil {
		t.Fatal("manifest bytes not covered by the attestation must be rejected")
	}
}

func TestPwnedBundleVerifierRejectsModifiedRange(t *testing.T) {
	directory, manifestPath, attestationPath, fingerprint := pwnedBundleFixture(t)
	rangePath := filepath.Join(directory, "00000.txt")
	file, err := os.OpenFile(rangePath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("tampered"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyPwnedBundle(directory, manifestPath, attestationPath, fingerprint, 4); err == nil {
		t.Fatal("range bytes not covered by the manifest must be rejected")
	}
}

func TestPwnedBundleVerifierRejectsMissingRange(t *testing.T) {
	directory, manifestPath, attestationPath, fingerprint := pwnedBundleFixture(t)
	if err := os.Remove(filepath.Join(directory, "00003.txt")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyPwnedBundle(directory, manifestPath, attestationPath, fingerprint, 4); err == nil {
		t.Fatal("missing range must reject the bundle")
	}
}
