package cli

// "fileparcel files put": the client side of the parted upload protocol
// (DESIGN §8.1). Local files and directories are scanned into one upload
// batch (declared in chunks of 1000 entries); files up to small_max go
// through the small-file path, larger ones are sent as part_size (8 MiB)
// parts with a SHA-256 per part, several parts in flight across files; each
// request is retried with exponential backoff. --zip bundles everything into
// one zip built by the server job upload.zip, which the command waits for.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/cli/clikit"
	"fileparcel/internal/core"
	"fileparcel/internal/names"
	"fileparcel/internal/ziputil"
)

// Upload protocol limits on the client side.
const (
	batchChunk     = 1000     // entries per create/add request (DESIGN §8.1)
	maxParallel    = 16       // upper bound of --parallel
	maxPartSize    = 64 << 20 // refuse absurd part sizes from a server
	defaultPartPar = 4        // fallback when the server does not say
	headerSHA256   = "X-FP-SHA256"
)

// localEntry is one file or (empty) directory to upload.
type localEntry struct {
	Path  string // local path (files)
	Rel   string // rel_path in the batch ("Trip/day1/a.jpg")
	Size  int64
	MTime time.Time
	Kind  string // core.UploadKindFile | core.UploadKindDir
	Ref   string // client_ref
}

// junkFiles are the operating systems' housekeeping files that uploads
// leave out, as the web UI does (upload/scan.js JUNK; lower case).
var junkFiles = []string{".ds_store", "thumbs.db", "desktop.ini", ".localized"}

// scanLocal walks the sources into upload entries. Symlinks named on the
// command line are followed (to a file or a directory, uploaded under the
// link's name); symlinks and special files found inside directories are
// skipped with a warning, and so are system files (junkFiles) with one
// line that counts them; a file named on the command line is always
// uploaded. Directories that end up without any uploaded entry are declared
// as "dir" entries so they are created too.
// rename (optional) replaces the top-level name of a single source.
func scanLocal(srcs []string, rename string, warn func(format string, a ...any)) ([]localEntry, error) {
	var out []localEntry
	tops := map[string]string{}
	nf, nd, junk := 0, 0, 0
	addFile := func(p, rel string, info fs.FileInfo) {
		nf++
		out = append(out, localEntry{Path: p, Rel: rel, Size: info.Size(), MTime: info.ModTime(), Kind: core.UploadKindFile, Ref: fmt.Sprintf("f%d", nf)})
	}
	for _, src := range srcs {
		abs, err := filepath.Abs(src)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, err
		}
		top := filepath.Base(abs)
		if rename != "" {
			top = rename
		}
		if top == string(filepath.Separator) || top == "." || top == ".." || top == "" {
			return nil, UsageError("cannot upload %q: name the directory itself, not the file system root", src)
		}
		key := names.Key(top)
		if prev, dup := tops[key]; dup {
			return nil, UsageError("%q and %q would both be uploaded as %q", prev, src, top)
		}
		tops[key] = src
		switch {
		case info.Mode().IsRegular():
			addFile(abs, top, info)
		case info.IsDir():
			// WalkDir does not descend into a symlinked root (it Lstats
			// it), so walk the directory the source points to — a link
			// named on the command line, or "." reached through one — and
			// keep the name the user gave (top) for the upload.
			root, err := filepath.EvalSymlinks(abs)
			if err != nil {
				return nil, err
			}
			hasChild := map[string]bool{}
			var dirs []string
			err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				relOS, err := filepath.Rel(root, p)
				if err != nil {
					return err
				}
				// Warnings name the path as the user gave it.
				shown := filepath.Join(abs, relOS)
				rel := top
				if relOS != "." {
					rel = top + "/" + filepath.ToSlash(relOS)
				}
				switch t := d.Type(); {
				case d.IsDir():
					dirs = append(dirs, rel)
					if rel != top {
						hasChild[path.Dir(rel)] = true
					}
				case t&fs.ModeSymlink != 0:
					warn("skipping symbolic link %s", shown)
				case t.IsRegular() && slices.Contains(junkFiles, strings.ToLower(d.Name())):
					junk++ // its folder is still created (empty, if nothing else is in it)
				case t.IsRegular():
					fi, err := d.Info()
					if err != nil {
						return err
					}
					addFile(p, rel, fi)
					hasChild[path.Dir(rel)] = true
				default:
					warn("skipping special file %s", shown)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			for _, d := range dirs {
				if !hasChild[d] {
					nd++
					out = append(out, localEntry{Rel: d, Kind: core.UploadKindDir, Ref: fmt.Sprintf("d%d", nd)})
				}
			}
		default:
			return nil, UsageError("cannot upload %q: not a regular file or directory", src)
		}
	}
	if junk > 0 {
		warn("left out %s (.DS_Store, Thumbs.db, desktop.ini, .localized)", Plural(int64(junk), "system file"))
	}
	for _, e := range out {
		if _, err := names.SplitRelPath(e.Rel); err != nil {
			msg := err.Error()
			if ce := core.AsError(err); ce != nil {
				msg = ce.Message
			}
			return nil, UsageError("cannot upload %q: %s", e.Rel, msg)
		}
	}
	return out, nil
}

// putOptions configures an upload.
type putOptions struct {
	Conflict core.ConflictPolicy
	ZipName  string // zip mode when set
	Parallel int    // 0 = server default
	Progress bool
	// ZipEncryption and ZipPassword protect the zip (zip mode only). The
	// password goes into the batch-create request only and is cleared right
	// after it (never in the complete call, job parameters or messages).
	ZipEncryption     string
	ZipPassword       string
	GeneratedPassword bool // ZipPassword was generated: it is printed once
	// created, when set, runs right after the batch was created, before any
	// data is sent (to print a generated zip password).
	created func(b *core.UploadBatch)
	// regenerate, when set (a generated zip password), makes a new password
	// of at least n characters; upload asks once for one as long as the
	// server's minimum when it refuses the generated one as too short.
	regenerate func(n int) string
}

// reZipPasswordMin finds the minimum in the server's refusal of a short
// .zip password ("the password must be at least 30 characters long").
var reZipPasswordMin = regexp.MustCompile(`at least (\d+) characters`)

// zipPasswordMinFrom returns the minimum length a 422 refusal of the field
// zip_password asks for (0 when err is not one).
func zipPasswordMinFrom(err error) int {
	ce := core.AsError(err)
	if ce == nil || ce.Code != core.ErrInvalid.Code || ce.Field != "zip_password" {
		return 0
	}
	m := reZipPasswordMin.FindStringSubmatch(ce.Message)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// lateUploadError is an error after the server accepted the batch's
// complete call: the zip may still be built.
type lateUploadError struct{ err error }

func (e *lateUploadError) Error() string { return e.err.Error() }
func (e *lateUploadError) Unwrap() error { return e.err }

// zipBatchError explains a refusal of the zip fields at batch creation: an
// older server does not know them; otherwise it names the rejected field.
func zipBatchError(err error) error {
	ce := core.AsError(err)
	if ce == nil || ce.Code != core.ErrInvalid.Code || (ce.Field != "zip_password" && ce.Field != "zip_encryption") {
		return err
	}
	if strings.Contains(ce.Message, "unknown field") {
		return &ExitCodeError{Code: ExitFailure, Err: errors.New("this server does not support password-protected .zip files (upgrade it)")}
	}
	what := "zip password"
	if ce.Field == "zip_encryption" {
		what = "zip encryption"
	}
	// The message names the field already ("zip_password: zip password …"
	// would say it twice).
	return &core.Error{Code: ce.Code, Status: ce.Status, Message: what + " rejected by the server: " + ce.Message}
}

// putResult summarises an upload.
type putResult struct {
	Batch     *core.UploadBatch
	Files     int
	Bytes     int64
	Committed int
	Skipped   int
	Elapsed   time.Duration
}

// uploader runs one batch.
type uploader struct {
	c     *Client
	cmd   *cobra.Command
	opts  putOptions
	prog  *clikit.Progress
	batch *core.UploadBatch
	pool  sync.Pool

	committed, skipped, filesDone atomic.Int64
	totalFiles                    int64
}

// partTask is one unit of work: a small file, a part, or the completion of a
// parted file whose parts are all present.
type partTask struct {
	e     *localEntry
	st    *core.UploadFileState
	part  int // -1 = small file; -2 = complete only
	left  *atomic.Int64
	count int
}

// upload uploads entries into folderID. o.ZipPassword is cleared once the
// batch is created.
func upload(ctx context.Context, cmd *cobra.Command, c *Client, folderID string, entries []localEntry, o *putOptions) (*putResult, error) {
	start := time.Now()
	u := &uploader{c: c, cmd: cmd, opts: *o}
	u.opts.ZipPassword = ""
	var total int64
	for _, e := range entries {
		if e.Kind == core.UploadKindFile {
			total += e.Size
			u.totalFiles++
		}
	}
	u.prog = clikit.NewProgress(cmd.ErrOrStderr(), o.Progress, "uploading", total)

	inputs := make([]core.UploadFileInput, len(entries))
	for i, e := range entries {
		in := core.UploadFileInput{ClientRef: e.Ref, RelPath: e.Rel, Size: e.Size, Kind: e.Kind}
		if !e.MTime.IsZero() {
			in.MTime = e.MTime.UnixMilli()
		}
		inputs[i] = in
	}
	mode := core.UploadModeFiles
	if o.ZipName != "" {
		mode = core.UploadModeZip
	}
	first := inputs[:min(len(inputs), batchChunk)]
	in := core.BatchInput{FolderID: folderID, Mode: mode, ZipName: o.ZipName, Conflict: o.Conflict, Files: first}
	if o.ZipPassword != "" {
		in.ZipEncryption, in.ZipPassword = cmp.Or(o.ZipEncryption, core.ZipEncAES256), core.Secret(o.ZipPassword)
	}
	var batch core.UploadBatch
	err := c.Do(ctx, http.MethodPost, api("/upload-batches"), in, &batch)
	if n := zipPasswordMinFrom(err); n > len(o.ZipPassword) && n <= ziputil.MaxPasswordLen && o.regenerate != nil {
		// A generated password shorter than storage.zip_password_min: the
		// refused batch was not created, so ask again with a longer one.
		o.ZipPassword = o.regenerate(n)
		in.ZipPassword = core.Secret(o.ZipPassword)
		err = c.Do(ctx, http.MethodPost, api("/upload-batches"), in, &batch)
	}
	in.ZipPassword, o.ZipPassword = "", "" // sent once; a generated one lives on in the caller only
	if err != nil {
		return nil, zipBatchError(err)
	}
	if batch.ID == "" {
		return nil, errors.New("the server did not return an upload batch id")
	}
	u.batch = &batch
	if o.created != nil {
		o.created(&batch)
	}
	ok := false
	defer func() {
		if !ok {
			u.abort()
		}
	}()

	states := map[string]*core.UploadFileState{}
	for i := range batch.Files {
		states[batch.Files[i].ClientRef] = &batch.Files[i]
	}
	for off := len(first); off < len(inputs); off += batchChunk {
		chunk := inputs[off:min(len(inputs), off+batchChunk)]
		var more []core.UploadFileState
		if err := c.Do(ctx, http.MethodPost, api("/upload-batches/"+pathEsc(batch.ID)+"/files"), chunk, &more); err != nil {
			return nil, err
		}
		for i := range more {
			states[more[i].ClientRef] = &more[i]
		}
	}
	partSize, smallMax := batch.PartSize, batch.SmallMax
	if partSize <= 0 {
		partSize = core.PartSize
	}
	if partSize > maxPartSize {
		return nil, fmt.Errorf("the server asks for %s parts; this client supports at most %s", HumanBytes(partSize), HumanBytes(maxPartSize))
	}
	if smallMax < 0 || smallMax > partSize {
		smallMax = partSize
	}
	u.pool.New = func() any { b := make([]byte, partSize); return &b }

	// Build the task list.
	var tasks []partTask
	for i := range entries {
		e := &entries[i]
		if e.Kind != core.UploadKindFile {
			continue
		}
		st := states[e.Ref]
		if st == nil {
			return nil, fmt.Errorf("the server did not acknowledge %q", e.Rel)
		}
		switch st.State {
		case core.UploadCommitted, core.UploadSkipped, core.UploadUploaded:
			if st.State == core.UploadSkipped {
				// --conflict skip onto a taken name: the server declared it
				// skipped, nothing is sent (nor counted as sent).
				total -= e.Size
			}
			u.finished(st, e)
			continue
		case core.UploadFailed, core.UploadAborted:
			return nil, fmt.Errorf("%s: %s", e.Rel, dash(st.Error))
		}
		if e.Size <= smallMax {
			tasks = append(tasks, partTask{e: e, st: st, part: -1})
			continue
		}
		count := st.PartCount
		want := int((e.Size + partSize - 1) / partSize)
		if count == 0 {
			count = want
		}
		if count != want {
			return nil, fmt.Errorf("%s: the server expects %d parts, the client computed %d", e.Rel, count, want)
		}
		var pending []int
		for n := range count {
			if !slices.Contains(st.PartsDone, n) {
				pending = append(pending, n)
			} else {
				u.prog.Add(partLen(e.Size, partSize, n))
			}
		}
		if len(pending) == 0 {
			tasks = append(tasks, partTask{e: e, st: st, part: -2})
			continue
		}
		left := new(atomic.Int64)
		left.Store(int64(len(pending)))
		for _, n := range pending {
			tasks = append(tasks, partTask{e: e, st: st, part: n, left: left, count: count})
		}
	}
	u.prog.SetTotal(total)

	par := o.Parallel
	if par <= 0 {
		par = batch.Parallel
	}
	if par <= 0 {
		par = defaultPartPar
	}
	par = min(par, maxParallel)

	u.prog.SetNote(u.note())
	u.prog.Start(200 * time.Millisecond)
	err = u.run(ctx, tasks, par, partSize)
	u.prog.Finish()
	if err != nil {
		return nil, err
	}

	var fin core.UploadBatch
	if err := u.retry(ctx, func() error {
		return c.Do(ctx, http.MethodPost, api("/upload-batches/"+pathEsc(batch.ID)+"/complete"), nil, &fin)
	}); err != nil {
		return nil, err
	}
	ok = true // from here on the batch is the server's to finish
	if fin.ID == "" {
		fin = batch
	}
	if fin.State == core.BatchFinalizing && fin.JobID != "" {
		if _, err := waitJob(ctx, cmd, c, fin.JobID, false, "building "+o.ZipName); err != nil {
			return nil, &lateUploadError{err}
		}
	}
	var final core.UploadBatch
	if err := c.Do(ctx, http.MethodGet, api("/upload-batches/"+pathEsc(batch.ID)), nil, &final); err == nil && final.ID != "" {
		fin = final
	}
	switch fin.State {
	case core.BatchFailed, core.BatchAborted, core.BatchExpired:
		return nil, &lateUploadError{fmt.Errorf("upload batch %s %s: %s", fin.ID, fin.State, dash(fin.Error))}
	}
	res := &putResult{Batch: &fin, Files: int(u.totalFiles), Bytes: total, Elapsed: time.Since(start),
		Committed: int(u.committed.Load()), Skipped: int(u.skipped.Load())}
	if len(fin.Files) > 0 {
		res.Committed, res.Skipped = 0, 0
		for _, f := range fin.Files {
			switch {
			case f.Kind == core.UploadKindDir:
			case f.State == core.UploadSkipped:
				res.Skipped++
			case f.State == core.UploadCommitted || f.State == core.UploadUploaded:
				res.Committed++
			}
		}
	}
	return res, nil
}

func (u *uploader) note() string {
	return fmt.Sprintf("%d/%d files", u.filesDone.Load(), u.totalFiles)
}

// finished records a file that reached a final state.
func (u *uploader) finished(st *core.UploadFileState, e *localEntry) {
	switch st.State {
	case core.UploadSkipped:
		u.skipped.Add(1)
	default:
		u.committed.Add(1)
	}
	u.filesDone.Add(1)
	if u.prog != nil {
		u.prog.SetNote(u.note())
	}
}

// abort cancels the batch after a failure (best effort, fresh context).
func (u *uploader) abort() {
	if u.batch == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = u.c.Do(ctx, http.MethodDelete, api("/upload-batches/"+pathEsc(u.batch.ID)), nil, nil)
}

// retry runs fn with the transfer backoff policy.
func (u *uploader) retry(ctx context.Context, fn func() error) error {
	return clikit.Retry(ctx, transferBackoff, isRetryable, func(int) error { return fn() })
}

// run executes the tasks with par workers; the first error stops the rest.
func (u *uploader) run(ctx context.Context, tasks []partTask, par int, partSize int64) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	ch := make(chan partTask)
	var wg sync.WaitGroup
	for range min(par, max(len(tasks), 1)) {
		wg.Go(func() {
			for t := range ch {
				if err := u.do(ctx, t, partSize); err != nil {
					cancel(err)
				}
			}
		})
	}
feed:
	for _, t := range tasks {
		select {
		case ch <- t:
		case <-ctx.Done():
			break feed
		}
	}
	close(ch)
	wg.Wait()
	if err := context.Cause(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return ctx.Err()
}

// do executes one task.
func (u *uploader) do(ctx context.Context, t partTask, partSize int64) error {
	if ctx.Err() != nil {
		return nil
	}
	switch t.part {
	case -1:
		return u.putSmall(ctx, t)
	case -2:
		return u.complete(ctx, t)
	}
	if err := u.putPart(ctx, t, partSize); err != nil {
		return err
	}
	if t.left.Add(-1) == 0 {
		return u.complete(ctx, t)
	}
	return nil
}

// partLen is the length of part n of a file of size bytes.
func partLen(size, partSize int64, n int) int64 {
	off := int64(n) * partSize
	return min(partSize, size-off)
}

// readSection reads length bytes at off from the entry's file into a pooled
// buffer, checking that the file did not change since it was scanned.
func (u *uploader) readSection(e *localEntry, off, length int64) (*[]byte, error) {
	f, err := os.Open(e.Path)
	if err != nil {
		return nil, fatalf("%s: %v", e.Path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fatalf("%s: %v", e.Path, err)
	}
	if fi.Size() != e.Size || !fi.ModTime().Equal(e.MTime) {
		return nil, fatalf("%s changed while it was being uploaded; run the upload again", e.Path)
	}
	bp := u.pool.Get().(*[]byte)
	buf := (*bp)[:length]
	if _, err := f.ReadAt(buf, off); err != nil && !(errors.Is(err, io.EOF) && length == 0) {
		u.pool.Put(bp)
		return nil, fatalf("%s: %v", e.Path, err)
	}
	return bp, nil
}

// sizedBody is a request body with a known length that reports its progress.
type sizedBody struct {
	r *clikit.CountingReader
	n int64
}

func (b *sizedBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *sizedBody) Size() int64                { return b.n }

// send PUTs data with its SHA-256 and retries; the progress contributed by a
// failed attempt is undone before the next one.
func (u *uploader) send(ctx context.Context, path string, data []byte, out any) error {
	sum := sha256.Sum256(data)
	hdr := http.Header{
		headerSHA256:   {hex.EncodeToString(sum[:])},
		"Content-Type": {"application/octet-stream"},
	}
	return u.retry(ctx, func() error {
		cr := &clikit.CountingReader{R: bytes.NewReader(data), P: u.prog}
		var body io.Reader = &sizedBody{r: cr, n: int64(len(data))}
		if len(data) == 0 {
			body = http.NoBody
		}
		resp, err := u.c.Stream(ctx, http.MethodPut, path, body, hdr)
		if err != nil {
			cr.Undo()
			return err
		}
		defer resp.Body.Close()
		if out != nil && resp.StatusCode != http.StatusNoContent {
			if err := decodeJSONBody(resp.Body, out); err != nil {
				return fatalf("decode response: %v", err)
			}
		} else {
			_, _ = io.Copy(io.Discard, resp.Body)
		}
		return nil
	})
}

func (u *uploader) putSmall(ctx context.Context, t partTask) error {
	bp, err := u.readSection(t.e, 0, t.e.Size)
	if err != nil {
		return err
	}
	defer u.pool.Put(bp)
	var st core.UploadFileState
	p := api("/upload-batches/"+pathEsc(u.batch.ID)+"/small", "ref", t.e.Ref)
	if err := u.send(ctx, p, (*bp)[:t.e.Size], &st); err != nil {
		return fmt.Errorf("upload %s: %w", t.e.Rel, err)
	}
	if st.State == core.UploadFailed {
		return fmt.Errorf("upload %s: %s", t.e.Rel, dash(st.Error))
	}
	if st.State == "" {
		st.State = core.UploadCommitted
	}
	u.finished(&st, t.e)
	return nil
}

func (u *uploader) putPart(ctx context.Context, t partTask, partSize int64) error {
	off := int64(t.part) * partSize
	n := partLen(t.e.Size, partSize, t.part)
	bp, err := u.readSection(t.e, off, n)
	if err != nil {
		return err
	}
	defer u.pool.Put(bp)
	p := api(fmt.Sprintf("/uploads/%s/parts/%d", pathEsc(t.st.ID), t.part))
	if err := u.send(ctx, p, (*bp)[:n], nil); err != nil {
		return fmt.Errorf("upload %s (part %d/%d): %w", t.e.Rel, t.part+1, t.count, err)
	}
	return nil
}

func (u *uploader) complete(ctx context.Context, t partTask) error {
	var st core.UploadFileState
	if err := u.retry(ctx, func() error {
		return u.c.Do(ctx, http.MethodPost, api("/uploads/"+pathEsc(t.st.ID)+"/complete"), nil, &st)
	}); err != nil {
		return fmt.Errorf("complete %s: %w", t.e.Rel, err)
	}
	if st.State == core.UploadFailed {
		return fmt.Errorf("upload %s: %s", t.e.Rel, dash(st.Error))
	}
	if st.State == "" {
		st.State = core.UploadCommitted
	}
	u.finished(&st, t.e)
	return nil
}

// decodeJSONBody decodes a JSON response body (an empty body is fine).
func decodeJSONBody(r io.Reader, out any) error {
	data, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// zipName normalizes a --zip value: a ".zip" extension is added when missing.
func zipName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", UsageError("--zip needs a file name")
	}
	if !strings.HasSuffix(strings.ToLower(s), ".zip") {
		s += ".zip"
	}
	if _, _, err := names.Clean(s); err != nil {
		return "", UsageError("--zip: invalid name %q: %v", s, err)
	}
	return s, nil
}
