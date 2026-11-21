package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	pwnedRangeCount       = 1 << 20
	pwnedRangeFileLimit   = 4 << 20
	pwnedRangeLineLimit   = 100_000
	pwnedDatasetByteLimit = uint64(256) << 30
	pwnedManifestVersion  = 1
)

type pwnedManifestHeader struct {
	Type         string "json:\"type\""
	Version      int    "json:\"version\""
	Source       string "json:\"source\""
	Hash         string "json:\"hash\""
	SnapshotDate string "json:\"snapshot_date\""
	GeneratedAt  string "json:\"generated_at\""
	RangeCount   int    "json:\"range_count\""
	TotalBytes   uint64 "json:\"total_bytes\""
	TotalRecords uint64 "json:\"total_records\""
}

type pwnedManifestEntry struct {
	Prefix  string "json:\"prefix\""
	Size    uint32 "json:\"size\""
	Records uint64 "json:\"records\""
	SHA256  string "json:\"sha256\""
}

func runCreatePwnedManifest(args []string) int {
	flags := newFlagSet("create-pwned-manifest")
	directory := flags.String("directory", "", "official SHA-1 PREFIX.txt directory")
	manifestPath := flags.String("manifest", "", "new JSONL manifest output path")
	snapshotDate := flags.String("snapshot-date", "", "operator-claimed dataset date (YYYY-MM-DD)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *directory == "" || *manifestPath == "" || *snapshotDate == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --directory, --manifest and --snapshot-date are required")
		return 2
	}
	header, digest, err := createPwnedManifest(*directory, *manifestPath, *snapshotDate, pwnedRangeCount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	fmt.Printf("OK: validated %d range files; %d records; %d bytes\nManifest SHA-256: %s\nSnapshot date claim: %s\n", header.RangeCount, header.TotalRecords, header.TotalBytes, digest, header.SnapshotDate)
	fmt.Fprintln(os.Stdout, "The manifest is unsigned. Keep its SHA-256 separately; it is not publisher authentication or proof of source completeness/freshness.")
	return 0
}

func runVerifyPwnedManifest(args []string) int {
	flags := newFlagSet("verify-pwned-manifest")
	directory := flags.String("directory", "", "official SHA-1 PREFIX.txt directory")
	manifestPath := flags.String("manifest", "", "JSONL manifest to verify")
	expectedDigest := flags.String("expected-sha256", "", "independently retained manifest SHA-256")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *directory == "" || *manifestPath == "" || *expectedDigest == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --directory, --manifest and --expected-sha256 are required")
		return 2
	}
	header, err := verifyPwnedManifest(*directory, *manifestPath, *expectedDigest, pwnedRangeCount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	fmt.Printf("OK: manifest and all %d range files match the independently retained SHA-256\nRecords: %d\nBytes: %d\nSnapshot date claim: %s\n", header.RangeCount, header.TotalRecords, header.TotalBytes, header.SnapshotDate)
	fmt.Fprintln(os.Stdout, "This verifies local byte integrity only; it does not authenticate HIBP as publisher or prove the claimed date, source completeness, or freshness.")
	return 0
}

func createPwnedManifest(directory, manifestPath, snapshotDate string, prefixCount int) (pwnedManifestHeader, string, error) {
	if prefixCount < 1 || prefixCount > pwnedRangeCount {
		return pwnedManifestHeader{}, "", errors.New("invalid expected prefix count")
	}
	snapshot, err := time.Parse("2006-01-02", snapshotDate)
	if err != nil || snapshot.After(time.Now().UTC().Truncate(24*time.Hour)) {
		return pwnedManifestHeader{}, "", errors.New("snapshot date must be a valid non-future YYYY-MM-DD date")
	}
	if err := ensureManifestOutsideDirectory(directory, manifestPath); err != nil {
		return pwnedManifestHeader{}, "", err
	}
	if _, err := scanPwnedRangeDirectory(directory, prefixCount); err != nil {
		return pwnedManifestHeader{}, "", err
	}
	output, err := os.OpenFile(manifestPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("cannot create manifest without overwriting an existing file: %w", err)
	}
	created := true
	defer func() {
		_ = output.Close()
		if created {
			_ = os.Remove(manifestPath)
		}
	}()
	entries, err := os.CreateTemp(filepath.Dir(manifestPath), ".pcage-pwned-entries-*")
	if err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("cannot create temporary entry file: %w", err)
	}
	entriesPath := entries.Name()
	defer func() {
		_ = entries.Close()
		_ = os.Remove(entriesPath)
	}()
	writer := bufio.NewWriterSize(entries, 1<<20)
	var totalBytes, totalRecords uint64
	encoder := json.NewEncoder(writer)
	for prefix := 0; prefix < prefixCount; prefix++ {
		entry, err := inspectPwnedRange(directory, prefix)
		if err != nil {
			return pwnedManifestHeader{}, "", fmt.Errorf("range %05X: %w", prefix, err)
		}
		if totalBytes > pwnedDatasetByteLimit-uint64(entry.Size) {
			return pwnedManifestHeader{}, "", errors.New("dataset exceeds the total byte safety limit")
		}
		if ^uint64(0)-totalRecords < entry.Records {
			return pwnedManifestHeader{}, "", errors.New("dataset record count overflow")
		}
		totalBytes += uint64(entry.Size)
		totalRecords += entry.Records
		if err := encoder.Encode(entry); err != nil {
			return pwnedManifestHeader{}, "", fmt.Errorf("cannot write range entry: %w", err)
		}
	}
	if totalRecords == 0 {
		return pwnedManifestHeader{}, "", errors.New("range directory contains no password hash records")
	}
	if err := writer.Flush(); err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("cannot flush range entries: %w", err)
	}
	if _, err := scanPwnedRangeDirectory(directory, prefixCount); err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("range directory changed during verification: %w", err)
	}
	header := pwnedManifestHeader{
		Type:         "pcage-pwned-password-ranges",
		Version:      pwnedManifestVersion,
		Source:       "HIBP-Pwned-Passwords",
		Hash:         "SHA-1",
		SnapshotDate: snapshotDate,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		RangeCount:   prefixCount,
		TotalBytes:   totalBytes,
		TotalRecords: totalRecords,
	}
	manifestWriter := bufio.NewWriterSize(output, 1<<20)
	if err := json.NewEncoder(manifestWriter).Encode(header); err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("cannot write manifest header: %w", err)
	}
	if _, err := entries.Seek(0, io.SeekStart); err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("cannot rewind manifest entries: %w", err)
	}
	if _, err := io.Copy(manifestWriter, entries); err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("cannot copy manifest entries: %w", err)
	}
	if err := manifestWriter.Flush(); err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("cannot flush manifest: %w", err)
	}
	if err := output.Sync(); err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("cannot sync manifest: %w", err)
	}
	if err := output.Close(); err != nil {
		return pwnedManifestHeader{}, "", fmt.Errorf("cannot close manifest: %w", err)
	}
	digest, err := hashPwnedManifest(manifestPath)
	if err != nil {
		return pwnedManifestHeader{}, "", err
	}
	created = false
	return header, digest, nil
}

func verifyPwnedManifest(directory, manifestPath, expectedDigest string, prefixCount int) (resultHeader pwnedManifestHeader, resultErr error) {
	if prefixCount < 1 || prefixCount > pwnedRangeCount {
		return pwnedManifestHeader{}, errors.New("invalid expected prefix count")
	}
	if !isHexDigest(expectedDigest) {
		return pwnedManifestHeader{}, errors.New("expected SHA-256 must contain exactly 64 hexadecimal characters")
	}
	if err := ensureManifestOutsideDirectory(directory, manifestPath); err != nil {
		return pwnedManifestHeader{}, err
	}
	file, info, err := openPwnedRegularFile(manifestPath)
	if err != nil {
		return pwnedManifestHeader{}, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cannot close manifest: %w", closeErr))
		}
	}()
	manifestSnapshot, err := createVerifiedPwnedManifestSnapshot(file, info.Size(), expectedDigest)
	if err != nil {
		return pwnedManifestHeader{}, err
	}
	snapshotPath := manifestSnapshot.Name()
	defer func() {
		closeErr := manifestSnapshot.Close()
		removeErr := os.Remove(snapshotPath)
		if cleanupErr := errors.Join(closeErr, removeErr); cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cannot clean manifest verification snapshot: %w", cleanupErr))
		}
	}()
	snapshotInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, snapshotInfo) || snapshotInfo.Size() != info.Size() || !snapshotInfo.ModTime().Equal(info.ModTime()) {
		return pwnedManifestHeader{}, errors.New("manifest changed while its verification snapshot was being created")
	}
	scanner := bufio.NewScanner(manifestSnapshot)
	scanner.Buffer(make([]byte, 4096), 4096)
	if !scanner.Scan() {
		return pwnedManifestHeader{}, errors.New("manifest header is missing")
	}
	var header pwnedManifestHeader
	if err := decodeStrictJSON(scanner.Bytes(), &header); err != nil {
		return pwnedManifestHeader{}, fmt.Errorf("invalid manifest header: %w", err)
	}
	if header.Type != "pcage-pwned-password-ranges" || header.Version != pwnedManifestVersion || header.Source != "HIBP-Pwned-Passwords" || header.Hash != "SHA-1" || header.RangeCount != prefixCount {
		return pwnedManifestHeader{}, errors.New("manifest header does not describe the supported complete SHA-1 range format")
	}
	snapshot, err := time.Parse("2006-01-02", header.SnapshotDate)
	if err != nil || snapshot.After(time.Now().UTC().Truncate(24*time.Hour)) {
		return pwnedManifestHeader{}, errors.New("manifest snapshot date is invalid or in the future")
	}
	if _, err := time.Parse(time.RFC3339, header.GeneratedAt); err != nil {
		return pwnedManifestHeader{}, errors.New("manifest generation timestamp is invalid")
	}
	if _, err := scanPwnedRangeDirectory(directory, prefixCount); err != nil {
		return pwnedManifestHeader{}, err
	}
	var totalBytes, totalRecords uint64
	for prefix := 0; prefix < prefixCount; prefix++ {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return pwnedManifestHeader{}, fmt.Errorf("manifest entry %05X is unreadable: %w", prefix, err)
			}
			return pwnedManifestHeader{}, fmt.Errorf("manifest entry %05X is missing", prefix)
		}
		var entry pwnedManifestEntry
		if err := decodeStrictJSON(scanner.Bytes(), &entry); err != nil {
			return pwnedManifestHeader{}, fmt.Errorf("manifest entry %05X is invalid: %w", prefix, err)
		}
		if entry.Prefix != fmt.Sprintf("%05X", prefix) || entry.Size > pwnedRangeFileLimit || entry.Records > pwnedRangeLineLimit || !isHexDigest(entry.SHA256) || entry.SHA256 != strings.ToUpper(entry.SHA256) || ((entry.Size == 0) != (entry.Records == 0)) {
			return pwnedManifestHeader{}, fmt.Errorf("manifest entry %05X has invalid prefix, size, count or digest", prefix)
		}
		if totalBytes > pwnedDatasetByteLimit-uint64(entry.Size) || ^uint64(0)-totalRecords < entry.Records {
			return pwnedManifestHeader{}, errors.New("manifest totals exceed supported limits")
		}
		totalBytes += uint64(entry.Size)
		totalRecords += entry.Records
		if err := verifyPwnedRangeDigest(directory, entry); err != nil {
			return pwnedManifestHeader{}, fmt.Errorf("range %05X: %w", prefix, err)
		}
	}
	if scanner.Scan() || scanner.Err() != nil {
		return pwnedManifestHeader{}, errors.New("manifest contains trailing or unreadable entries")
	}
	if totalBytes != header.TotalBytes || totalRecords != header.TotalRecords || totalRecords == 0 {
		return pwnedManifestHeader{}, errors.New("manifest totals do not match its entries")
	}
	if _, err := scanPwnedRangeDirectory(directory, prefixCount); err != nil {
		return pwnedManifestHeader{}, fmt.Errorf("range directory changed during verification: %w", err)
	}
	finalInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, finalInfo) || finalInfo.Size() != info.Size() || !finalInfo.ModTime().Equal(info.ModTime()) {
		return pwnedManifestHeader{}, errors.New("manifest changed while it was being verified")
	}
	return header, nil
}

func createVerifiedPwnedManifestSnapshot(source *os.File, size int64, expectedDigest string) (snapshot *os.File, resultErr error) {
	if size < 0 || size > 128<<20 {
		return nil, errors.New("manifest size is outside the 128 MiB input limit")
	}
	if !isHexDigest(expectedDigest) {
		return nil, errors.New("expected SHA-256 must contain exactly 64 hexadecimal characters")
	}
	temporary, err := os.CreateTemp("", "pcage-pwned-manifest-verify-*")
	if err != nil {
		return nil, fmt.Errorf("cannot create manifest verification snapshot: %w", err)
	}
	keep := false
	defer func() {
		if keep {
			return
		}
		closeErr := temporary.Close()
		removeErr := os.Remove(temporary.Name())
		if cleanupErr := errors.Join(closeErr, removeErr); cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cannot clean failed manifest snapshot: %w", cleanupErr))
		}
	}()
	digest := sha256.New()
	limited := &io.LimitedReader{R: source, N: size}
	copied, err := io.Copy(io.MultiWriter(temporary, digest), limited)
	if err != nil {
		return nil, fmt.Errorf("cannot snapshot manifest: %w", err)
	}
	if copied != size || limited.N != 0 {
		return nil, errors.New("manifest was truncated while being snapshotted")
	}
	if !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), expectedDigest) {
		return nil, errors.New("manifest SHA-256 does not match the independently retained digest")
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("cannot rewind manifest verification snapshot: %w", err)
	}
	keep = true
	return temporary, nil
}

func scanPwnedRangeDirectory(directory string, prefixCount int) ([]byte, error) {
	if prefixCount < 1 || prefixCount > pwnedRangeCount {
		return nil, errors.New("invalid expected prefix count")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("range path must be a real directory, not a symbolic link")
	}
	dir, err := os.Open(directory)
	if err != nil {
		return nil, fmt.Errorf("cannot open range directory: %w", err)
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("range directory changed while opening")
	}
	seen := make([]byte, (prefixCount+7)/8)
	found := 0
	for {
		names, readErr := dir.Readdirnames(4096)
		for _, name := range names {
			if name == "sha1.index" {
				indexInfo, err := os.Lstat(filepath.Join(directory, name))
				if err != nil || !indexInfo.Mode().IsRegular() || indexInfo.Mode()&os.ModeSymlink != 0 {
					return nil, errors.New("sha1.index must be a regular non-symbolic file when present")
				}
				continue
			}
			prefix, ok := parsePwnedRangeFilename(name)
			if !ok || int(prefix) >= prefixCount {
				return nil, fmt.Errorf("unexpected entry %q in range directory", name)
			}
			index := int(prefix) / 8
			bit := byte(1 << (uint(prefix) % 8))
			if seen[index]&bit != 0 {
				return nil, fmt.Errorf("duplicate prefix %05X", prefix)
			}
			seen[index] |= bit
			found++
		}
		if readErr == io.EOF {
			break
		}
		if readErr == nil && len(names) == 0 {
			return nil, errors.New("directory enumeration returned no entries without EOF")
		}
		if readErr != nil {
			return nil, fmt.Errorf("cannot enumerate range directory: %w", readErr)
		}
	}
	if found != prefixCount {
		return nil, fmt.Errorf("range directory contains %d of %d required PREFIX.txt files", found, prefixCount)
	}
	for prefix := 0; prefix < prefixCount; prefix++ {
		if seen[prefix/8]&(1<<uint(prefix%8)) == 0 {
			return nil, fmt.Errorf("required range %05X.txt is missing", prefix)
		}
	}
	finalInfo, err := os.Stat(directory)
	if err != nil || !os.SameFile(info, finalInfo) || !finalInfo.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("range directory entries changed during enumeration")
	}
	return seen, nil
}

func inspectPwnedRange(directory string, prefix int) (pwnedManifestEntry, error) {
	path := filepath.Join(directory, fmt.Sprintf("%05X.txt", prefix))
	file, info, err := openPwnedRegularFile(path)
	if err != nil {
		return pwnedManifestEntry{}, err
	}
	defer file.Close()
	if info.Size() < 0 || info.Size() > pwnedRangeFileLimit {
		return pwnedManifestEntry{}, fmt.Errorf("range exceeds %d bytes", pwnedRangeFileLimit)
	}
	limited := &io.LimitedReader{R: file, N: info.Size()}
	digest := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(limited, digest))
	scanner.Split(splitPwnedLines)
	scanner.Buffer(make([]byte, 64), 64)
	previous := ""
	var records uint64
	for scanner.Scan() {
		line := scanner.Bytes()
		if err := validatePwnedRecord(line, previous); err != nil {
			return pwnedManifestEntry{}, fmt.Errorf("record %d: %w", records+1, err)
		}
		previous = string(line[:35])
		records++
		if records > pwnedRangeLineLimit {
			return pwnedManifestEntry{}, errors.New("range exceeds the record limit")
		}
	}
	if err := scanner.Err(); err != nil {
		return pwnedManifestEntry{}, err
	}
	if limited.N != 0 {
		return pwnedManifestEntry{}, errors.New("range was truncated while being read")
	}
	finalInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, finalInfo) || finalInfo.Size() != info.Size() || !finalInfo.ModTime().Equal(info.ModTime()) {
		return pwnedManifestEntry{}, errors.New("range changed while being read")
	}
	return pwnedManifestEntry{Prefix: fmt.Sprintf("%05X", prefix), Size: uint32(info.Size()), Records: records, SHA256: strings.ToUpper(hex.EncodeToString(digest.Sum(nil)))}, nil
}

func verifyPwnedRangeDigest(directory string, entry pwnedManifestEntry) error {
	file, info, err := openPwnedRegularFile(filepath.Join(directory, entry.Prefix+".txt"))
	if err != nil {
		return err
	}
	defer file.Close()
	if info.Size() != int64(entry.Size) {
		return errors.New("range size does not match manifest")
	}
	digest := sha256.New()
	copied, err := io.CopyN(digest, file, info.Size())
	if err != nil || copied != info.Size() {
		return errors.New("range file could not be read completely")
	}
	finalInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, finalInfo) || finalInfo.Size() != info.Size() || !finalInfo.ModTime().Equal(info.ModTime()) {
		return errors.New("range changed while its digest was checked")
	}
	if !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), entry.SHA256) {
		return errors.New("range SHA-256 does not match manifest")
	}
	return nil
}

func validatePwnedRecord(line []byte, previous string) error {
	if len(line) < 37 || len(line) > 56 || line[35] != ':' {
		return errors.New("record must be a 35-character suffix followed by a positive count")
	}
	for _, c := range line[:35] {
		if !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F') {
			return errors.New("suffix must be uppercase hexadecimal")
		}
	}
	suffix := string(line[:35])
	if previous != "" && suffix <= previous {
		return errors.New("suffix records are not strictly increasing")
	}
	countText := string(line[36:])
	for _, c := range countText {
		if c < '0' || c > '9' {
			return errors.New("occurrence count must be decimal")
		}
	}
	count, err := strconv.ParseUint(countText, 10, 64)
	if err != nil || count == 0 || strconv.FormatUint(count, 10) != countText {
		return errors.New("occurrence count must be a positive canonical uint64")
	}
	return nil
}

func splitPwnedLines(data []byte, atEOF bool) (int, []byte, error) {
	if index := bytes.IndexByte(data, '\n'); index >= 0 {
		line := data[:index]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		return index + 1, line, nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func parsePwnedRangeFilename(name string) (uint32, bool) {
	if len(name) != 9 || name[5:] != ".txt" {
		return 0, false
	}
	var value uint32
	for _, c := range name[:5] {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value |= uint32(c - '0')
		case c >= 'A' && c <= 'F':
			value |= uint32(c-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func openPwnedRegularFile(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot inspect file: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("path is not a regular non-symbolic file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open file: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, errors.New("file path changed while opening")
	}
	return file, opened, nil
}

func hashPwnedManifest(path string) (string, error) {
	file, info, err := openPwnedRegularFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if info.Size() > 128<<20 {
		return "", errors.New("manifest exceeds the 128 MiB input limit")
	}
	digest := sha256.New()
	if _, err := io.CopyN(digest, file, info.Size()); err != nil {
		return "", fmt.Errorf("cannot hash manifest: %w", err)
	}
	finalInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, finalInfo) || finalInfo.Size() != info.Size() || !finalInfo.ModTime().Equal(info.ModTime()) {
		return "", errors.New("manifest changed while it was being hashed")
	}
	return strings.ToUpper(hex.EncodeToString(digest.Sum(nil))), nil
}

func decodeStrictJSON(data []byte, target any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("JSON line must contain exactly one value")
	}
	return nil
}

func isHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func ensureManifestOutsideDirectory(directory, manifest string) error {
	dir, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(manifest)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	if err != nil {
		return err
	}
	if rel == "." || (!filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("manifest output must be outside the range directory")
	}
	return nil
}
