package cli

// "fileparcel files get": single files via GET /nodes/{id}/content with
// resumable partial downloads (Range + If-Range on "<dest>.fpart", whose
// "<dest>.fpart.ver" records the node and version the bytes came from) and
// content-hash verification; folders (or --zip/--tar) via a single-use
// archive ticket (POST /archives → GET /api/v1/archives/{ticket}), streamed.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"fileparcel/internal/cli/clikit"
	"fileparcel/internal/core"
	"fileparcel/internal/names"
)

// partialSuffix marks an unfinished download next to its destination;
// partialVersionSuffix (appended to the partial file's name) marks the record
// of the node and version its bytes came from.
const (
	partialSuffix        = ".fpart"
	partialVersionSuffix = ".ver"
)

// partialPath returns the partial download file of dest: "<dest>.fpart", or,
// when that or its version record would not fit in a file name
// (names.MaxNameBytes), the name shortened at a character boundary plus a
// hash of the full name. It depends on dest only, so running the same
// command again finds the same file.
func partialPath(dest string) string {
	dir, base := filepath.Split(dest)
	if len(base)+len(partialSuffix)+len(partialVersionSuffix) <= names.MaxNameBytes {
		return dest + partialSuffix
	}
	sum := sha256.Sum256([]byte(base))
	tag := "~" + hex.EncodeToString(sum[:4])
	return dir + fitBytes(base, names.MaxNameBytes-len(tag)-len(partialSuffix)-len(partialVersionSuffix)) + tag + partialSuffix
}

// fitBytes shortens s at a character boundary to at most n bytes.
func fitBytes(s string, n int) string {
	for len(s) > max(n, 0) {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// removePartial deletes a partial download file and its version record (a
// symlink at either path is removed itself, its target is not touched).
func removePartial(part string) {
	_ = os.Remove(part)
	_ = os.Remove(part + partialVersionSuffix)
}

// createPartial starts the partial file part afresh. source (when set) is
// recorded first, so an existing partial file always has an accurate record.
// Whatever was at either path is removed, and O_EXCL never follows a symlink:
// the data only ever lands in a new file of our own, not in a file someone
// planted there (in a shared directory).
func createPartial(part, source string) (*os.File, error) {
	removePartial(part)
	if source != "" {
		m, err := os.OpenFile(part+partialVersionSuffix, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		_, werr := m.WriteString(source + "\n")
		if err := m.Close(); werr == nil {
			werr = err
		}
		if werr != nil {
			return nil, werr
		}
	}
	return os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// openChecked opens path and makes sure it is still the file fi (from
// os.Lstat) describes: a symlink or another file swapped in after the check
// is refused rather than written to or read.
func openChecked(path string, fi fs.FileInfo, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, err
	}
	if ofi, err := f.Stat(); err != nil || !os.SameFile(fi, ofi) {
		f.Close()
		return nil, fmt.Errorf("%s was replaced while it was being opened", path)
	}
	return f, nil
}

// partialSource reads the version record of the partial file part ("" when
// there is none this user wrote).
func partialSource(part string) string {
	meta := part + partialVersionSuffix
	fi, err := os.Lstat(meta)
	if err != nil || !ownPrivateFile(fi) || fi.Size() > 1024 {
		return ""
	}
	f, err := openChecked(meta, fi, os.O_RDONLY)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(string(b), "\n")
}

// getOptions configures a download.
type getOptions struct {
	Force    bool   // overwrite an existing destination
	Resume   bool   // continue an existing .fpart
	Version  string // ver_… (files only)
	Progress bool
}

// getResult is the --json output of files get.
type getResult struct {
	Node     *core.Node `json:"node"`
	Path     string     `json:"path"` // local path ("-" = stdout)
	Bytes    int64      `json:"bytes"`
	Resumed  int64      `json:"resumed_from,omitempty"`
	Archive  string     `json:"archive,omitempty"` // zip | tar
	Verified bool       `json:"verified"`          // content hash checked
}

// localDest picks the local destination: dest "" → ./name; an existing
// directory → dir/name; "-" → stdout. Only a dest given as "-" means stdout:
// a remote file called "-" is written to "./-" (see joinLocal).
func localDest(dest, name string) (string, error) {
	if strings.ContainsAny(name, `/\`) || name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("refusing unsafe remote file name %q", name)
	}
	switch {
	case dest == "-":
		return "-", nil
	case dest == "":
		return joinLocal(".", name), nil
	}
	if fi, err := os.Stat(dest); err == nil && fi.IsDir() {
		return joinLocal(dest, name), nil
	}
	if strings.HasSuffix(dest, string(filepath.Separator)) || strings.HasSuffix(dest, "/") {
		return "", fmt.Errorf("%s: no such directory", dest)
	}
	return dest, nil
}

// joinLocal joins dir and a name that comes from the server. The result is
// never the stdout marker "-": filepath.Join(".", "-") is "-" itself.
func joinLocal(dir, name string) string {
	p := filepath.Join(dir, name)
	if p == "-" {
		p = "." + string(filepath.Separator) + p
	}
	return p
}

// downloadFile downloads a file node to dest (see localDest), resuming a
// previous partial download when possible and verifying size and content
// hash.
func downloadFile(ctx context.Context, cmd *cobra.Command, c *Client, n *core.Node, dest string, o getOptions) (*getResult, error) {
	dest, err := localDest(dest, n.Name)
	if err != nil {
		return nil, err
	}
	size, hash, version := n.Size, n.ContentHash, n.VersionID
	if o.Version != "" {
		vs, err := doList[core.FileVersion](ctx, c, http.MethodGet, api("/nodes/"+pathEsc(n.ID)+"/versions"), nil)
		if err != nil {
			return nil, err
		}
		found := false
		for _, v := range vs {
			if v.ID == o.Version {
				size, hash, version, found = v.Size, v.ContentHash, v.ID, true
			}
		}
		if !found {
			return nil, core.Errorf(core.ErrNotFound, "%s has no version %s (see \"fileparcel files versions\")", n.Name, o.Version)
		}
	}
	contentPath := api("/nodes/"+pathEsc(n.ID)+"/content", "version", o.Version)
	res := &getResult{Node: n, Path: dest}

	if dest == "-" {
		h := clikit.NewContentHasher()
		resp, err := c.Stream(ctx, http.MethodGet, contentPath, nil, nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		written, err := io.Copy(io.MultiWriter(cmd.OutOrStdout(), h), resp.Body)
		if err != nil {
			return nil, err
		}
		res.Bytes = written
		if err := verifyDownload(written, size, h, hash); err != nil {
			return nil, err
		}
		res.Verified = clikit.ComparableContentHash(hash)
		return res, nil
	}

	if !o.Force && fileExists(dest) {
		return nil, fmt.Errorf("%s already exists (use --force to overwrite)", dest)
	}
	part := partialPath(dest)
	// The bytes in part are only continued when their record says they come
	// from this very node and version. A partial file of an older version
	// (the file was replaced since), of another file with the same name or
	// of an older client would otherwise be completed with the wrong bytes;
	// If-Range cannot tell, as it carries the version resolved in this run.
	source := n.ID + " " + version
	if !o.Resume || partialSource(part) != source {
		removePartial(part)
	}
	prog := clikit.NewProgress(cmd.ErrOrStderr(), o.Progress, Truncate(n.Name, 30), size)
	prog.Start(200 * time.Millisecond)
	defer prog.Finish()

	etag := strconv.Quote(version)
	first := true
	err = clikit.Retry(ctx, transferBackoff, isRetryable, func(int) error {
		off := int64(0)
		// Only a private regular file of ours is continued (Lstat: never
		// through a symlink); anything else is replaced by a new file.
		pfi, err := os.Lstat(part)
		if err == nil && ownPrivateFile(pfi) {
			off = pfi.Size()
		}
		if off > size {
			off = 0
		}
		if first {
			res.Resumed = off
			first = false
		}
		prog.Add(off - prog.Done())
		if off == size && off > 0 {
			return nil // complete already; verified below
		}
		hdr := http.Header{}
		if off > 0 && version != "" {
			hdr.Set("Range", fmt.Sprintf("bytes=%d-", off))
			hdr.Set("If-Range", etag)
		} else {
			off = 0
		}
		resp, err := c.Stream(ctx, http.MethodGet, contentPath, nil, hdr)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var f *os.File
		var ferr error
		switch resp.StatusCode {
		case http.StatusPartialContent:
			// Only a range this run asked for (off > 0: part is a private
			// file of ours, see above) is appended to.
			start, err := contentRangeStart(resp.Header.Get("Content-Range"))
			if err != nil || start != off || off == 0 {
				return fatalf("unexpected Content-Range %q for a resume at byte %d", resp.Header.Get("Content-Range"), off)
			}
			f, ferr = openChecked(part, pfi, os.O_WRONLY|os.O_APPEND)
		default:
			off = 0
			prog.Add(-prog.Done())
			f, ferr = createPartial(part, source)
		}
		if ferr != nil {
			return fatalf("%v", ferr)
		}
		_, cerr := io.Copy(&clikit.CountingWriter{W: f, P: prog}, resp.Body)
		if err := f.Close(); err != nil && cerr == nil {
			cerr = err
		}
		return cerr
	})
	prog.Finish()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("interrupted; run the same command again to resume (%s)", part)
		}
		return nil, err
	}
	fi, err := os.Lstat(part)
	if err != nil {
		return nil, err
	}
	if !ownPrivateFile(fi) {
		removePartial(part)
		return nil, fmt.Errorf("%s was replaced during the download; run the command again", part)
	}
	h := clikit.NewContentHasher()
	if clikit.ComparableContentHash(hash) {
		f, err := openChecked(part, fi, os.O_RDONLY)
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	if err := verifyDownload(fi.Size(), size, h, hash); err != nil {
		removePartial(part)
		return nil, err
	}
	if err := os.Rename(part, dest); err != nil {
		return nil, err
	}
	_ = os.Remove(part + partialVersionSuffix)
	mt := n.UpdatedAt
	if n.ClientMtime != nil && o.Version == "" {
		mt = *n.ClientMtime
	}
	if !mt.IsZero() {
		_ = os.Chtimes(dest, mt, mt)
	}
	res.Bytes = fi.Size()
	res.Verified = clikit.ComparableContentHash(hash)
	return res, nil
}

// verifyDownload checks the size and (when known) the content hash; h must
// have hashed the whole file unless the hash is not comparable.
func verifyDownload(got, want int64, h *clikit.ContentHasher, hash string) error {
	if got != want {
		return fmt.Errorf("download incomplete: got %d of %d bytes; run the command again", got, want)
	}
	if clikit.ComparableContentHash(hash) {
		if sum := h.Sum(); sum != hash {
			return fmt.Errorf("downloaded data does not match the server's content hash (%s ≠ %s); the partial file was removed, run the command again", sum, hash)
		}
	}
	return nil
}

// contentRangeStart parses "bytes START-END/TOTAL".
func contentRangeStart(v string) (int64, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(v), "bytes ")
	if !ok {
		return 0, errors.New("bad Content-Range")
	}
	start, _, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, errors.New("bad Content-Range")
	}
	return strconv.ParseInt(strings.TrimSpace(start), 10, 64)
}

// downloadArchive streams nodes as a zip or tar archive to dest (default
// ./<name>.<format>).
func downloadArchive(ctx context.Context, cmd *cobra.Command, c *Client, nodes []core.Node, name, format, dest string, o getOptions) (*getResult, error) {
	// A folder name may take all of names.MaxNameBytes; shorten it so the
	// extension fits, as the server does for the archive's own name.
	fname := fitBytes(name, names.MaxNameBytes-len(format)-1) + "." + format
	dest, err := localDest(dest, fname)
	if err != nil {
		return nil, err
	}
	if dest != "-" && !o.Force && fileExists(dest) {
		return nil, fmt.Errorf("%s already exists (use --force to overwrite)", dest)
	}
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	var tk core.ArchiveTicketResponse
	if err := c.Do(ctx, http.MethodPost, api("/archives"), core.ArchiveInput{NodeIDs: ids, Format: format, Name: name}, &tk); err != nil {
		return nil, err
	}
	p := tk.URL
	if p == "" {
		p = api("/archives/" + pathEsc(tk.Ticket))
	}
	if u, err := url.Parse(p); err == nil && u.IsAbs() {
		p = u.RequestURI()
	}
	resp, err := c.Stream(ctx, http.MethodGet, p, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	res := &getResult{Path: dest, Archive: format}
	if len(nodes) == 1 {
		res.Node = &nodes[0]
	}
	if dest == "-" {
		n, err := io.Copy(cmd.OutOrStdout(), resp.Body)
		res.Bytes = n
		return res, err
	}
	prog := clikit.NewProgress(cmd.ErrOrStderr(), o.Progress, Truncate(fname, 30), 0)
	prog.Start(200 * time.Millisecond)
	part := partialPath(dest)
	f, err := createPartial(part, "")
	if err != nil {
		prog.Finish()
		return nil, err
	}
	n, cerr := io.Copy(&clikit.CountingWriter{W: f, P: prog}, resp.Body)
	if err := f.Close(); err != nil && cerr == nil {
		cerr = err
	}
	prog.Finish()
	if cerr != nil {
		_ = os.Remove(part)
		return nil, fmt.Errorf("archive download failed (archives cannot be resumed; run the command again): %w", cerr)
	}
	if err := os.Rename(part, dest); err != nil {
		return nil, err
	}
	res.Bytes = n
	return res, nil
}
