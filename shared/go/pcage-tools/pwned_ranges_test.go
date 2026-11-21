package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makePwnedTestDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "ranges")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"00000.txt": "00000000000000000000000000000000000:1\r\n10000000000000000000000000000000000:2\r\n",
		"00001.txt": "",
		"00002.txt": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9",
		"00003.txt": "ABCDEF0123456789ABCDEF0123456789ABC:3\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "sha1.index"), []byte("ignored downloader metadata\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestPwnedManifestCreateAndVerifyCompleteDirectory(t *testing.T) {
	root := t.TempDir()
	directory := makePwnedTestDirectory(t)
	manifest := filepath.Join(root, "ranges.jsonl")
	header, digest, err := createPwnedManifest(directory, manifest, "2026-11-18", 4)
	if err != nil {
		t.Fatal(err)
	}
	if header.RangeCount != 4 || header.TotalRecords != 4 || len(digest) != 64 {
		t.Fatalf("unexpected manifest summary: %+v digest=%q", header, digest)
	}
	verified, err := verifyPwnedManifest(directory, manifest, digest, 4)
	if err != nil {
		t.Fatal(err)
	}
	if verified.TotalBytes != header.TotalBytes || verified.TotalRecords != header.TotalRecords {
		t.Fatalf("verified totals differ: %+v vs %+v", verified, header)
	}
}

func TestPwnedManifestRejectsMissingUnexpectedAndMalformedRanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) error
	}{
		{"missing prefix", func(directory string) error { return os.Remove(filepath.Join(directory, "00003.txt")) }},
		{"unexpected file", func(directory string) error { return os.WriteFile(filepath.Join(directory, "partial.tmp"), []byte("x"), 0600) }},
		{"malformed suffix", func(directory string) error { return os.WriteFile(filepath.Join(directory, "00002.txt"), []byte("bad:1\n"), 0600) }},
		{"duplicate suffix", func(directory string) error {
			return os.WriteFile(filepath.Join(directory, "00002.txt"), []byte("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:2\n"), 0600)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			directory := makePwnedTestDirectory(t)
			if err := test.mutate(directory); err != nil {
				t.Fatal(err)
			}
			if _, _, err := createPwnedManifest(directory, filepath.Join(root, "ranges.jsonl"), "2026-11-18", 4); err == nil {
				t.Fatal("expected invalid range directory to be rejected")
			}
		})
	}
}

func TestPwnedManifestRejectsSymlinkRange(t *testing.T) {
	root := t.TempDir()
	directory := makePwnedTestDirectory(t)
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("00000000000000000000000000000000000:1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, "00003.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "00003.txt")); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if _, _, err := createPwnedManifest(directory, filepath.Join(root, "ranges.jsonl"), "2026-11-18", 4); err == nil {
		t.Fatal("expected symlink range to be rejected")
	}
}

func TestPwnedManifestRejectsAllEmptyRanges(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "empty")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for prefix := 0; prefix < 4; prefix++ {
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("%05X.txt", prefix)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := createPwnedManifest(directory, filepath.Join(root, "empty.jsonl"), "2026-11-18", 4); err == nil {
		t.Fatal("all-empty range directory must not be attested")
	}
}

func TestPwnedManifestDetectsRangeAndManifestTampering(t *testing.T) {
	root := t.TempDir()
	directory := makePwnedTestDirectory(t)
	manifest := filepath.Join(root, "ranges.jsonl")
	_, digest, err := createPwnedManifest(directory, manifest, "2026-11-18", 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "00002.txt"), []byte("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE:9\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPwnedManifest(directory, manifest, digest, 4); err == nil {
		t.Fatal("changed range bytes must fail verification")
	}
	if err := os.WriteFile(filepath.Join(directory, "00002.txt"), []byte("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9"), 0600); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-2] ^= 1
	if err := os.WriteFile(manifest, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPwnedManifest(directory, manifest, digest, 4); err == nil {
		t.Fatal("manifest tampering must fail the independent digest check")
	}
}

func TestPwnedManifestRefusesOverwriteAndFutureSnapshot(t *testing.T) {
	root := t.TempDir()
	directory := makePwnedTestDirectory(t)
	manifest := filepath.Join(root, "ranges.jsonl")
	if err := os.WriteFile(manifest, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := createPwnedManifest(directory, manifest, "2026-11-18", 4); err == nil {
		t.Fatal("existing manifest must not be overwritten")
	}
	contents, err := os.ReadFile(manifest)
	if err != nil || string(contents) != "keep" {
		t.Fatal("existing manifest changed")
	}
	future := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02")
	if _, _, err := createPwnedManifest(directory, filepath.Join(root, "future.jsonl"), future, 4); err == nil {
		t.Fatal("future snapshot date must be rejected")
	}
}

func TestPwnedManifestRejectsDigestMismatchAndDuplicateJSONKeys(t *testing.T) {
	root := t.TempDir()
	directory := makePwnedTestDirectory(t)
	manifest := filepath.Join(root, "ranges.jsonl")
	_, digest, err := createPwnedManifest(directory, manifest, "2026-11-18", 4)
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Repeat("0", sha256.Size*2)
	if _, err := verifyPwnedManifest(directory, manifest, wrong, 4); err == nil {
		t.Fatal("wrong manifest digest must be rejected")
	}
	if err := decodeStrictJSON([]byte("{\"type\":\"a\",\"type\":\"b\"}"), &map[string]string{}); err == nil {
		t.Fatal("duplicate JSON keys must be rejected")
	}
	if !isHexDigest(digest) || digest != strings.ToUpper(digest) {
		t.Fatal("generated digest is not canonical hexadecimal")
	}
}

func TestPwnedManifestHeaderJSONRejectsUnknownFields(t *testing.T) {
	data := []byte("{\"type\":\"pcage-pwned-password-ranges\",\"version\":1,\"source\":\"HIBP-Pwned-Passwords\",\"hash\":\"SHA-1\",\"snapshot_date\":\"2026-11-18\",\"generated_at\":\"2026-11-19T10:00:00Z\",\"range_count\":4,\"total_bytes\":10,\"total_records\":1,\"unexpected\":true}")
	var header pwnedManifestHeader
	if err := decodeStrictJSON(data, &header); err == nil {
		t.Fatal("unknown JSON fields must be rejected")
	}
}

func TestPwnedRangeCountsMatchSharedKotlinUnsigned64Contract(t *testing.T) {
	readVector := func(name string) []byte {
		t.Helper()
		path := filepath.Join("..", "..", "crypto", "test-vectors", "pwned-password-ranges", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read shared vector %s: %v", name, err)
		}
		return []byte(strings.TrimSpace(string(data)))
	}

	maximum := readVector("uint64-max.txt")
	if len(maximum) != 56 {
		t.Fatalf("maximum unsigned record has %d bytes; want 56", len(maximum))
	}
	if err := validatePwnedRecord(maximum, ""); err != nil {
		t.Fatalf("maximum unsigned 64-bit count should be accepted: %v", err)
	}

	overflow := readVector("uint64-overflow.txt")
	if err := validatePwnedRecord(overflow, ""); err == nil {
		t.Fatal("count greater than uint64 must be rejected")
	}
}



func TestPwnedManifestSharedCrossLanguageVector(t *testing.T) {
	vectorRoot := filepath.Join("..", "..", "crypto", "test-vectors", "pwned-password-manifest", "v1")
	directory := filepath.Join(vectorRoot, "ranges")
	manifest := filepath.Join(vectorRoot, "manifest.jsonl")
	digestBytes, err := os.ReadFile(filepath.Join(vectorRoot, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyPwnedManifest(directory, manifest, strings.TrimSpace(string(digestBytes)), 4)
	if err != nil {
		t.Fatal(err)
	}
	if verified.RangeCount != 4 || verified.TotalBytes != 193 || verified.TotalRecords != 5 {
		t.Fatalf("unexpected shared manifest totals: %+v", verified)
	}
}


func TestPwnedManifestSnapshotBindsBytesBeforeSourceMutation(t *testing.T) {
	root := t.TempDir()
	directory := makePwnedTestDirectory(t)
	manifest := filepath.Join(root, "ranges.jsonl")
	_, digest, err := createPwnedManifest(directory, manifest, "2026-11-18", 4)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	source, info, err := openPwnedRegularFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	snapshot, err := createVerifiedPwnedManifestSnapshot(source, info.Size(), digest)
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath := snapshot.Name()
	t.Cleanup(func() {
		if err := snapshot.Close(); err != nil {
			t.Errorf("close snapshot: %v", err)
		}
		if err := os.Remove(snapshotPath); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove snapshot: %v", err)
		}
	})

	changed := strings.Replace(string(original), "\"snapshot_date\":\"2026-11-18\"", "\"snapshot_date\":\"2026-11-19\"", 1)
	if changed == string(original) {
		t.Fatal("test manifest did not contain the expected snapshot date")
	}
	if err := os.WriteFile(manifest, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(manifest, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	snapshotBytes, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshotBytes) != string(original) {
		t.Fatal("digest-bound snapshot changed after the source manifest was rewritten")
	}
	if _, err := verifyPwnedManifest(directory, manifest, digest, 4); err == nil {
		t.Fatal("a fresh verification must reject the rewritten source manifest")
	}
}

func TestPwnedManifestSnapshotRejectsTruncationAfterSizeCapture(t *testing.T) {
	root := t.TempDir()
	directory := makePwnedTestDirectory(t)
	manifest := filepath.Join(root, "ranges.jsonl")
	_, digest, err := createPwnedManifest(directory, manifest, "2026-11-18", 4)
	if err != nil {
		t.Fatal(err)
	}
	source, info, err := openPwnedRegularFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	writer, err := os.OpenFile(manifest, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Truncate(info.Size() - 1); err != nil {
		_ = writer.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := createVerifiedPwnedManifestSnapshot(source, info.Size(), digest); err == nil {
		if snapshot != nil {
			_ = snapshot.Close()
			_ = os.Remove(snapshot.Name())
		}
		t.Fatal("a manifest truncated after size capture must not produce a verified snapshot")
	}
}
