package ziputil

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"fileparcel/internal/ziputil/ziputiltest"
)

// The 7-Zip fixtures in testdata were made with 7-Zip 25.01 from the files in
// testdata/7z-src (plus an empty directory "dir", which git cannot hold):
//
//	printf 'hello, fileparcel\n' > text.txt; yes 'the quick brown fox' | head -c 20000 > fox.txt
//	head -c 5000 /dev/urandom > rand.bin; : > empty.txt; mkdir dir
//	7z a -tzip -mem=AES256    -mx=5 -p'correct horse battery staple' 7z-aes256.zip   text.txt fox.txt rand.bin empty.txt dir
//	7z a -tzip -mem=ZipCrypto -mx=5 -p'correct horse battery staple' 7z-zipcrypto.zip text.txt fox.txt rand.bin empty.txt dir
func TestReaderAgainst7zFixtures(t *testing.T) {
	src := map[string][]byte{}
	for _, name := range []string{"text.txt", "fox.txt", "rand.bin", "empty.txt"} {
		b, err := os.ReadFile(filepath.Join("testdata", "7z-src", name))
		if err != nil {
			t.Fatal(err)
		}
		src[name] = b
	}
	for _, c := range []struct{ file, enc string }{{"7z-aes256.zip", "aes256"}, {"7z-zipcrypto.zip", "zipcrypto"}} {
		b, err := os.ReadFile(filepath.Join("testdata", c.file))
		if err != nil {
			t.Fatal(err)
		}
		es, err := ziputiltest.ReadBytes(b, katPassword)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		seen := map[string]bool{}
		for _, e := range es {
			seen[e.Name] = true
			if e.Name == "dir/" {
				if !e.Dir || e.Encryption != "" {
					t.Errorf("%s: directory entry %+v", c.file, e)
				}
				continue
			}
			want, ok := src[e.Name]
			if !ok {
				t.Errorf("%s: unexpected entry %q", c.file, e.Name)
				continue
			}
			if !bytes.Equal(e.Data, want) || e.Encryption != c.enc {
				t.Errorf("%s: %s read as %d bytes, %q", c.file, e.Name, len(e.Data), e.Encryption)
			}
			if c.enc == "aes256" && e.AEVersion != 2 {
				t.Errorf("%s: %s is AE-%d", c.file, e.Name, e.AEVersion)
			}
		}
		if len(seen) != len(src)+1 || !seen["dir/"] {
			t.Errorf("%s: entries %v", c.file, seen)
		}
		if _, err := ziputiltest.ReadBytes(b, wrongPlainPW); err == nil {
			t.Errorf("%s: a wrong password read it", c.file)
		}
	}
}

// run runs a tool with a UTF-8 locale and returns its exit code and output.
func run(t *testing.T, name string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8", "LANG=C.UTF-8")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		return ee.ExitCode(), string(out)
	case err != nil:
		t.Fatalf("%s: %v", name, err)
	}
	return 0, string(out)
}

// extractAndCompare extracts archive with 7z x and compares the result with
// set (compareTree).
func extractAndCompare(t *testing.T, sz, archive string, set []entrySpec) {
	t.Helper()
	dir := t.TempDir()
	if code, out := run(t, sz, "x", "-y", "-p"+katPassword, "-o"+dir, archive); code != 0 {
		t.Fatalf("7z x exited %d:\n%s", code, out)
	}
	compareTree(t, "7z x", dir, set)
}

// unzipAndCompare extracts archive with Info-ZIP unzip and compares the
// result with set (compareTree).
func unzipAndCompare(t *testing.T, unzip, archive string, set []entrySpec) {
	t.Helper()
	dir := t.TempDir()
	if code, out := run(t, unzip, "-q", "-P", katPassword, "-d", dir, archive); code != 0 {
		t.Fatalf("unzip exited %d:\n%s", code, out)
	}
	compareTree(t, "unzip", dir, set)
}

// compareTree checks that the tree extracted into dir by tool holds exactly
// the files of set, byte for byte, and its directories.
func compareTree(t *testing.T, tool, dir string, set []entrySpec) {
	t.Helper()
	got := map[string][]byte{}
	var dirs []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			dirs = append(dirs, filepath.ToSlash(rel)+"/")
			return nil
		}
		b, err := os.ReadFile(p)
		got[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, e := range set {
		if e.dir {
			if !strings.Contains(strings.Join(dirs, "\n")+"\n", e.name+"\n") {
				t.Errorf("%s: directory %s missing (have %v)", tool, e.name, dirs)
			}
			continue
		}
		files++
		if b, ok := got[e.name]; !ok || !bytes.Equal(b, e.data) {
			t.Errorf("%s: %s differs (extracted: %v, %d bytes; want %d bytes)", tool, e.name, ok, len(b), len(e.data))
		}
	}
	if len(got) != files {
		t.Errorf("%s extracted %d files, want %d: %v", tool, len(got), files, keys(got))
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// sevenZipList parses `7z l -slt` into path → property → value.
func sevenZipList(t *testing.T, sz, archive string) map[string]map[string]string {
	t.Helper()
	code, out := run(t, sz, "l", "-slt", "-p"+katPassword, archive)
	if code != 0 {
		t.Fatalf("7z l exited %d:\n%s", code, out)
	}
	_, body, ok := strings.Cut(out, "\n----------\n")
	if !ok {
		t.Fatalf("7z l output without a file list:\n%s", out)
	}
	res := map[string]map[string]string{}
	var cur map[string]string
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		if k == "Path" {
			cur = map[string]string{}
			res[v] = cur
		}
		if cur != nil {
			cur[k] = v
		}
	}
	return res
}

func writeArchive(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestInterop7z: 7-Zip tests, lists and extracts the archives of the round
// trip tests byte-identically, and rejects a wrong password; Info-ZIP unzip
// does the same for ZipCrypto. Extracting and comparing matters: a wrong
// counter still passes `7z t` for AE-2 Store entries (no CRC, and the MAC
// covers the ciphertext).
func TestInterop7z(t *testing.T) {
	sz := ziputiltest.Require7z(t)
	for _, enc := range []Encryption{EncryptionAES256, EncryptionZipCrypto} {
		for _, comp := range []Compression{CompressionAuto, CompressionStore} {
			t.Run(string(enc)+"/"+string(comp), func(t *testing.T) {
				set := roundTripSet()
				archive := writeArchive(t, buildSet(t, Options{Compression: comp, Encryption: enc, Password: katPassword}, set))
				if code, out := run(t, sz, "t", "-p"+katPassword, archive); code != 0 {
					t.Fatalf("7z t exited %d:\n%s", code, out)
				}
				extractAndCompare(t, sz, archive, set)
				if code, out := run(t, sz, "t", "-pWrongPassword", archive); code != 2 {
					t.Errorf("7z t with a wrong password exited %d, want 2:\n%s", code, out)
				}

				list := sevenZipList(t, sz, archive)
				prefix := map[Encryption]string{EncryptionAES256: "AES-256 ", EncryptionZipCrypto: "ZipCrypto "}[enc]
				for _, e := range set {
					p := strings.TrimSuffix(e.name, "/")
					props, ok := list[p]
					if !ok {
						t.Errorf("7z l: %s missing", p)
						continue
					}
					wantMethod, wantEnc := "Store", "-"
					if !e.dir {
						inner := "Store"
						if comp == CompressionAuto && e.inner == 8 {
							inner = "Deflate"
						}
						wantMethod, wantEnc = prefix+inner, "+"
					}
					if props["Method"] != wantMethod || props["Encrypted"] != wantEnc {
						t.Errorf("7z l: %s is %q, Encrypted = %s; want %q, %s", p, props["Method"], props["Encrypted"], wantMethod, wantEnc)
					}
				}

				if enc == EncryptionZipCrypto {
					unzip := ziputiltest.RequireUnzip(t)
					if code, out := run(t, unzip, "-P", katPassword, "-tq", archive); code != 0 {
						t.Errorf("unzip -t exited %d:\n%s", code, out)
					}
					unzipAndCompare(t, unzip, archive, set)
					if code, _ := run(t, unzip, "-P", "wrong", "-tq", archive); code == 0 {
						t.Error("unzip -t accepted a wrong password")
					}
				}
			})
		}
	}
}

// TestInteropDescriptor: 7-Zip and unzip read entries written with a data
// descriptor (the 0xFFFFFFFF edge, forced here on small entries).
func TestInteropDescriptor(t *testing.T) {
	sz := ziputiltest.Require7z(t)
	forceDescriptor(t, "forced.txt", "forced.bin")
	for _, enc := range []Encryption{EncryptionAES256, EncryptionZipCrypto} {
		set := descriptorSet()
		archive := writeArchive(t, buildSet(t, Options{Encryption: enc, Password: katPassword}, set))
		if code, out := run(t, sz, "t", "-p"+katPassword, archive); code != 0 {
			t.Fatalf("%s: 7z t exited %d:\n%s", enc, code, out)
		}
		extractAndCompare(t, sz, archive, set)
		if enc == EncryptionZipCrypto {
			unzip := ziputiltest.RequireUnzip(t)
			if code, out := run(t, unzip, "-P", katPassword, "-tq", archive); code != 0 {
				t.Errorf("unzip -t exited %d:\n%s", code, out)
			}
			unzipAndCompare(t, unzip, archive, set)
		}
	}
}

// TestInteropLongestPassword: an archive protected with the longest accepted
// password opens in 7-Zip (AES-256 and ZipCrypto) and unzip (ZipCrypto).
// 7-Zip refuses WinZip AES passwords over 99 bytes and then reports a wrong
// password, so MaxPasswordLen may never go above that.
func TestInteropLongestPassword(t *testing.T) {
	if MaxPasswordLen > 99 {
		t.Fatalf("MaxPasswordLen = %d; 7-Zip opens WinZip AES archives with passwords of at most 99 bytes", MaxPasswordLen)
	}
	sz := ziputiltest.Require7z(t)
	pw := strings.Repeat("Kx7-9fQz!", MaxPasswordLen/9+1)[:MaxPasswordLen]
	for _, enc := range []Encryption{EncryptionAES256, EncryptionZipCrypto} {
		t.Run(string(enc), func(t *testing.T) {
			set := []entrySpec{{name: "a.txt", data: []byte("longest password\n"), inner: 8}}
			archive := writeArchive(t, buildSet(t, Options{Encryption: enc, Password: pw}, set))
			if code, out := run(t, sz, "t", "-p"+pw, archive); code != 0 {
				t.Fatalf("7z t with a %d-byte password exited %d:\n%s", len(pw), code, out)
			}
			dir := t.TempDir()
			if code, out := run(t, sz, "x", "-y", "-p"+pw, "-o"+dir, archive); code != 0 {
				t.Fatalf("7z x exited %d:\n%s", code, out)
			}
			compareTree(t, "7z x", dir, set)
			if code, out := run(t, sz, "t", "-p"+pw[:len(pw)-1], archive); code != 2 {
				t.Errorf("7z t with the password minus its last byte exited %d, want 2:\n%s", code, out)
			}
			if enc == EncryptionZipCrypto {
				unzip := ziputiltest.RequireUnzip(t)
				if code, out := run(t, unzip, "-P", pw, "-tq", archive); code != 0 {
					t.Errorf("unzip -t exited %d:\n%s", code, out)
				}
			}
		})
	}
}
