package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	pwnedAttestationFormat = "pcage-pwned-manifest-attestation"
	pwnedAttestationVersion = 1
	pwnedAttestationAlgorithm = "ECDSA-P256-SHA256"
	pwnedAttestationDomain = "PCAGE-PWNED-MANIFEST-ATTESTATION\x00V1\x00"
	pwnedAttestationFileLimit = 4 * 1024
)

type pwnedManifestAttestation struct {
	Format string `json:"format"`
	Version int `json:"version"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	ManifestSHA256 string `json:"manifest_sha256"`
	SignerPublicKeyX509Base64 string `json:"signer_public_key_x509_base64"`
	SignerPublicKeySHA256 string `json:"signer_public_key_sha256"`
	SignatureBase64 string `json:"signature_base64"`
}

func readPwnedAttestationFile(path string) (data []byte, resultErr error) {
	file, info, err := openPwnedRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cannot close attestation file: %w", closeErr))
		}
	}()
	if info.Size() <= 0 || info.Size() > pwnedAttestationFileLimit {
		return nil, errors.New("attestation file is empty or exceeds the 4 KiB input limit")
	}
	data, err = io.ReadAll(io.LimitReader(file, info.Size()))
	if err != nil {
		return nil, fmt.Errorf("cannot read attestation file: %w", err)
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("attestation file was truncated while being read")
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat attestation after reading: %w", err)
	}
	if !os.SameFile(info, finalInfo) || finalInfo.Size() != info.Size() || !finalInfo.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("attestation file changed while being read")
	}
	return data, nil
}

func hashPwnedManifestForAttestation(path string) (digest string, resultErr error) {
	file, info, err := openPwnedRegularFile(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cannot close manifest: %w", closeErr))
		}
	}()
	if info.Size() <= 0 || info.Size() > 128<<20 {
		return "", errors.New("manifest is empty or exceeds the 128 MiB input limit")
	}
	hasher := sha256.New()
	copied, err := io.CopyN(hasher, file, info.Size())
	if err != nil {
		return "", fmt.Errorf("cannot read manifest: %w", err)
	}
	if copied != info.Size() {
		return "", errors.New("manifest was truncated while being hashed")
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot stat manifest after hashing: %w", err)
	}
	if !os.SameFile(info, finalInfo) || finalInfo.Size() != info.Size() || !finalInfo.ModTime().Equal(info.ModTime()) {
		return "", errors.New("manifest changed while being hashed")
	}
	return strings.ToUpper(hex.EncodeToString(hasher.Sum(nil))), nil
}

func verifyPwnedManifestAttestation(data []byte, trustedFingerprint string) (string, string, error) {
	if len(data) == 0 || len(data) > pwnedAttestationFileLimit {
		return "", "", errors.New("attestation is empty or exceeds the 4 KiB input limit")
	}
	if !isHexDigest(trustedFingerprint) {
		return "", "", errors.New("trusted public-key fingerprint must be 64 hexadecimal characters")
	}
	var attestation pwnedManifestAttestation
	if err := decodeStrictJSON(data, &attestation); err != nil {
		return "", "", fmt.Errorf("invalid attestation JSON: %w", err)
	}
	if attestation.Format != pwnedAttestationFormat ||
		attestation.Version != pwnedAttestationVersion ||
		attestation.SignatureAlgorithm != pwnedAttestationAlgorithm {
		return "", "", errors.New("unsupported Pwned Passwords attestation format or algorithm")
	}
	if !isHexDigest(attestation.ManifestSHA256) || attestation.ManifestSHA256 != strings.ToUpper(attestation.ManifestSHA256) ||
		!isHexDigest(attestation.SignerPublicKeySHA256) || attestation.SignerPublicKeySHA256 != strings.ToUpper(attestation.SignerPublicKeySHA256) {
		return "", "", errors.New("attestation digests must be canonical uppercase SHA-256 values")
	}
	if len(attestation.SignerPublicKeyX509Base64) == 0 || len(attestation.SignerPublicKeyX509Base64) > 512 ||
		len(attestation.SignatureBase64) == 0 || len(attestation.SignatureBase64) > 256 {
		return "", "", errors.New("attestation key or signature exceeds its encoded size limit")
	}

	publicKeyBytes, err := base64.StdEncoding.Strict().DecodeString(attestation.SignerPublicKeyX509Base64)
	if err != nil {
		return "", "", fmt.Errorf("attestation public key is not valid Base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(publicKeyBytes) != attestation.SignerPublicKeyX509Base64 || len(publicKeyBytes) == 0 || len(publicKeyBytes) > 256 {
		return "", "", errors.New("attestation public key is not canonical bounded Base64")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("attestation public key is invalid: %w", err)
	}
	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != elliptic.P256().Params().Name ||
		!publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return "", "", errors.New("attestation public key must use the P-256 curve")
	}
	canonicalPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("cannot canonicalize attestation public key: %w", err)
	}
	if subtle.ConstantTimeCompare(canonicalPublicKey, publicKeyBytes) != 1 {
		return "", "", errors.New("attestation public key is not canonical X.509 SubjectPublicKeyInfo data")
	}

	fingerprintDigest := sha256.Sum256(publicKeyBytes)
	fingerprint := strings.ToUpper(hex.EncodeToString(fingerprintDigest[:]))
	if attestation.SignerPublicKeySHA256 != fingerprint {
		return "", "", errors.New("attestation public-key fingerprint does not match its key")
	}
	trustedBytes, err := hex.DecodeString(strings.ToUpper(trustedFingerprint))
	if err != nil {
		return "", "", fmt.Errorf("trusted public-key fingerprint is invalid: %w", err)
	}
	actualFingerprintBytes, err := hex.DecodeString(fingerprint)
	if err != nil {
		return "", "", fmt.Errorf("cannot decode calculated public-key fingerprint: %w", err)
	}
	if subtle.ConstantTimeCompare(trustedBytes, actualFingerprintBytes) != 1 {
		return "", "", errors.New("attestation signer does not match the independently trusted fingerprint")
	}

	signatureBytes, err := base64.StdEncoding.Strict().DecodeString(attestation.SignatureBase64)
	if err != nil {
		return "", "", fmt.Errorf("attestation signature is not valid Base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(signatureBytes) != attestation.SignatureBase64 ||
		len(signatureBytes) == 0 || len(signatureBytes) > 128 {
		return "", "", errors.New("attestation signature is not canonical bounded Base64")
	}
	manifestDigestBytes, err := hex.DecodeString(attestation.ManifestSHA256)
	if err != nil {
		return "", "", fmt.Errorf("attestation manifest digest is invalid: %w", err)
	}
	message := append([]byte(pwnedAttestationDomain), manifestDigestBytes...)
	message = append(message, fingerprintDigest[:]...)
	messageDigest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(publicKey, messageDigest[:], signatureBytes) {
		return "", "", errors.New("attestation signature is invalid")
	}
	return attestation.ManifestSHA256, fingerprint, nil
}

func runVerifyPwnedAttestation(args []string) int {
	flags := newFlagSet("verify-pwned-attestation")
	attestationPath := flags.String("attestation", "", "local manifest attestation JSON file")
	manifestPath := flags.String("manifest", "", "JSONL manifest whose bytes must match the attestation")
	trustedFingerprint := flags.String("trusted-public-key-sha256", "", "public-key SHA-256 confirmed through a separate trusted channel")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *attestationPath == "" || *manifestPath == "" || *trustedFingerprint == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --attestation, --manifest and --trusted-public-key-sha256 are required")
		return 2
	}
	attestationBytes, err := readPwnedAttestationFile(*attestationPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	attestedDigest, fingerprint, err := verifyPwnedManifestAttestation(attestationBytes, *trustedFingerprint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	actualDigest, err := hashPwnedManifestForAttestation(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	if subtle.ConstantTimeCompare([]byte(actualDigest), []byte(attestedDigest)) != 1 {
		fmt.Fprintln(os.Stderr, "ERROR: selected manifest bytes do not match the signed manifest SHA-256")
		return 1
	}
	fmt.Printf("OK: local Pwned Passwords manifest attestation signature is valid.\nManifest SHA-256: %s\nSigner public-key SHA-256: %s\n", attestedDigest, fingerprint)
	fmt.Fprintln(os.Stdout, "The signer fingerprint matches the independently supplied trust anchor. This does not authenticate HIBP, prove every range file is complete, or establish a trusted timestamp.")
	return 0
}
