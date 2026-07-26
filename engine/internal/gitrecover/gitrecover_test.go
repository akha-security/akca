package gitrecover

import "testing"

func TestParseHEADRef(t *testing.T) {
	ref, hash := ParseHEAD("ref: refs/heads/main\n")
	if ref != "refs/heads/main" || hash != "" {
		t.Fatalf("unexpected ref=%q hash=%q", ref, hash)
	}
}

func TestParseHEADDetached(t *testing.T) {
	h := "0123456789abcdef0123456789abcdef01234567"
	ref, hash := ParseHEAD(h)
	if ref != "" || hash != h {
		t.Fatalf("unexpected detached parse ref=%q hash=%q", ref, hash)
	}
}

func TestObjectStoragePath(t *testing.T) {
	got := ObjectStoragePath("aabbccddeeff0011223344556677889900aabbccdd")
	want := "/.git/objects/aa/bbccddeeff0011223344556677889900aabbccdd"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestExtractIndexPathsDIRC(t *testing.T) {
	body := []byte("DIRC\x00\x00\x00\x02" + "\x00src/main.php\x00app/config.yml\x00")
	paths := ExtractIndexPaths(body)
	if len(paths) < 1 {
		t.Fatalf("expected index paths, got %v", paths)
	}
}

func TestIsGitHEAD(t *testing.T) {
	if !IsGitHEAD("ref: refs/heads/master") {
		t.Fatal("expected valid HEAD")
	}
}

func TestExtractCommitHashes(t *testing.T) {
	hashes := ExtractCommitHashes("abc 1234567890123456789012345678901234567890 def")
	if len(hashes) != 1 {
		t.Fatalf("expected one hash, got %v", hashes)
	}
}
