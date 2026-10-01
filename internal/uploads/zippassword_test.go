package uploads

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/events"
	"fileparcel/internal/ids"
	"fileparcel/internal/uploads/uploadtest"
	"fileparcel/internal/ziputil"
	"fileparcel/internal/ziputil/ziputiltest"
)

// goodZipPW passes every rule of checkZipPassword.
const goodZipPW = "correct horse battery staple"

// zipEntry is one entry of a test batch.
type zipEntry struct {
	rel  string
	data []byte
	dir  bool
}

// testMtime is the client mtime every test entry declares (deterministic zips).
const testMtime = int64(1726700000000)

// protectedBatch declares a zip batch of entries with the given protection.
func (f *fixture) protectedBatch(a core.UploadActor, name, enc, pw string, entries []zipEntry) *core.UploadBatch {
	f.t.Helper()
	in := core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: name,
		ZipEncryption: enc, ZipPassword: core.Secret(pw)}
	for i, e := range entries {
		fi := core.UploadFileInput{ClientRef: fmt.Sprint("e", i), RelPath: e.rel, Size: int64(len(e.data)), MTime: testMtime}
		if e.dir {
			fi.Kind, fi.Size = core.UploadKindDir, 0
		}
		in.Files = append(in.Files, fi)
	}
	return f.batch(a, in)
}

// sendAll uploads every file entry of b (small path or parts).
func (f *fixture) sendAll(a core.UploadActor, b *core.UploadBatch, entries []zipEntry) {
	f.t.Helper()
	byRel := map[string][]byte{}
	for _, e := range entries {
		byRel[e.rel] = e.data
	}
	for _, fs := range b.Files {
		if fs.Kind == core.UploadKindDir {
			continue
		}
		data := byRel[fs.RelPath]
		if len(data) <= SmallMax {
			f.small(a, b.ID, fs.ClientRef, data)
			continue
		}
		order := make([]int, 0, fs.PartCount)
		for n := range fs.PartCount {
			order = append(order, n)
		}
		f.parts(a, fs.ID, data, order...)
		if _, err := f.svc.CompleteFile(f.ctx, a, fs.ID); err != nil {
			f.t.Fatalf("complete %s: %v", fs.RelPath, err)
		}
	}
}

// sealedPW returns the zip_password_enc column of a batch ("" for NULL).
func (f *fixture) sealedPW(batchID string) string {
	return f.Str(`SELECT zip_password_enc FROM upload_batches WHERE id = ?`, batchID)
}

// runZip completes b (jobs are manual) and runs its job.
func (f *fixture) runZip(a core.UploadActor, b *core.UploadBatch) (*core.UploadBatch, error) {
	f.t.Helper()
	fin := f.complete(a, b.ID)
	if fin.State != core.BatchFinalizing || fin.JobID == "" {
		f.t.Fatalf("complete: %+v", fin)
	}
	return fin, f.Jobs.Run(fin.JobID)
}

func TestZipPasswordValidation(t *testing.T) {
	f := setup(t)
	a := f.actor(f.alice)
	req := f.requestActor(f.alice, f.share(f.alice, f.aliceRoot, nil), "")
	const (
		msgCharset = "use only letters, digits, spaces and the symbols on a US keyboard " +
			"(unzip apps disagree on how other characters are encoded)"
		msgSpace   = "the password must not start or end with a space"
		msgSimple  = "the password is too simple; use more different characters"
		msgCommon  = "this password is too common; choose something less predictable"
		msgRequest = "password-protected .zip files are not available for file requests"
		msgMode    = "a .zip password needs mode zip"
		msgEnc     = "zip_encryption must be aes256 or zipcrypto"
		msgLegacy  = "ZipCrypto is turned off on this server; use AES-256"
		msgEmpty   = "enter a password for the .zip"
	)
	type setting struct {
		key string
		val any
	}
	cases := []struct {
		name          string
		actor         *core.UploadActor
		mode, enc, pw string
		set           []setting
		field, msg    string // "" = accepted
		want          string // accepted: the batch's zip_encryption
	}{
		{name: "unprotected", mode: "zip"},
		{name: "password only means aes256", mode: "zip", pw: goodZipPW, want: core.ZipEncAES256},
		{name: "aes256", mode: "zip", enc: "aes256", pw: goodZipPW, want: core.ZipEncAES256},
		{name: "zipcrypto", mode: "zip", enc: "zipcrypto", pw: goodZipPW, want: core.ZipEncZipCrypto},
		{name: "12 characters", mode: "zip", pw: "Xk9#mQ2vLp7!", want: core.ZipEncAES256},
		{name: "99 characters", mode: "zip", pw: strings.Repeat("Xk9#mQ2vLp7!", 8) + "Xk9", want: core.ZipEncAES256},
		{name: "99 characters zipcrypto", mode: "zip", enc: "zipcrypto", pw: strings.Repeat("Xk9#mQ2vLp7!", 8) + "Xk9", want: core.ZipEncZipCrypto},
		{name: "inner spaces", mode: "zip", pw: "a b c d e f g h", want: core.ZipEncAES256},

		// §4.1 rules, in their order.
		{name: "non-ASCII", mode: "zip", pw: "pässwörd-lang-genug", field: "zip_password", msg: msgCharset},
		{name: "control character", mode: "zip", pw: "Xk9#mQ2v\tLp7!", field: "zip_password", msg: msgCharset},
		{name: "DEL", mode: "zip", pw: "Xk9#mQ2vLp7!\x7f", field: "zip_password", msg: msgCharset},
		{name: "non-ASCII before length", mode: "zip", pw: "é", field: "zip_password", msg: msgCharset},
		{name: "too short", mode: "zip", pw: "Xk9#mQ2vLp7", field: "zip_password",
			msg: "the password must be at least 12 characters long"},
		{name: "too long", mode: "zip", pw: strings.Repeat("Xk9#mQ2vLp7!", 8) + "Xk9#", field: "zip_password",
			msg: "the password must be at most 99 characters long"},
		{name: "too long zipcrypto", mode: "zip", enc: "zipcrypto", pw: strings.Repeat("Xk9#mQ2vLp7!", 10) + "Xk9#mQ2v",
			field: "zip_password", msg: "the password must be at most 99 characters long"},
		{name: "leading space", mode: "zip", pw: " Xk9#mQ2vLp7!", field: "zip_password", msg: msgSpace},
		{name: "trailing space", mode: "zip", pw: "Xk9#mQ2vLp7! ", field: "zip_password", msg: msgSpace},
		{name: "few characters", mode: "zip", pw: "abababababababab", field: "zip_password", msg: msgSimple},
		{name: "few characters ignoring case", mode: "zip", pw: "AaBbCcAaBbCcAaBb", field: "zip_password", msg: msgSimple},
		{name: "common", mode: "zip", pw: "Password1234!", field: "zip_password", msg: msgCommon},
		{name: "common with spaces", mode: "zip", pw: "qwerty uiop 2024", field: "zip_password", msg: msgCommon},

		// storage.zip_password_min, clamped to 8..64.
		{name: "min 16", mode: "zip", pw: "Xk9#mQ2vLp7!zRt", set: []setting{{SettingZipPasswordMin, 16}},
			field: "zip_password", msg: "the password must be at least 16 characters long"},
		{name: "min 16 met", mode: "zip", pw: "Xk9#mQ2vLp7!zRt5", set: []setting{{SettingZipPasswordMin, 16}},
			want: core.ZipEncAES256},
		{name: "min below the floor", mode: "zip", pw: "Xk9#mQ2v", set: []setting{{SettingZipPasswordMin, 2}},
			want: core.ZipEncAES256},
		{name: "min below the floor still 8", mode: "zip", pw: "Xk9#mQ2", set: []setting{{SettingZipPasswordMin, 2}},
			field: "zip_password", msg: "the password must be at least 8 characters long"},
		{name: "min above the ceiling", mode: "zip", pw: strings.Repeat("Xk9#mQ2v", 8), set: []setting{{SettingZipPasswordMin, 500}},
			want: core.ZipEncAES256},

		// zipProtection steps.
		{name: "file request", actor: &req, mode: "zip", pw: goodZipPW, field: "zip_password", msg: msgRequest},
		{name: "file request, encryption only", actor: &req, mode: "zip", enc: "aes256", field: "zip_encryption", msg: msgRequest},
		{name: "file request, files mode", actor: &req, pw: goodZipPW, field: "zip_password", msg: msgRequest},
		{name: "files mode", mode: "files", pw: goodZipPW, field: "zip_password", msg: msgMode},
		{name: "default mode", pw: goodZipPW, field: "zip_password", msg: msgMode},
		{name: "files mode, encryption only", mode: "files", enc: "zipcrypto", field: "zip_encryption", msg: msgMode},
		{name: "unknown method", mode: "zip", enc: "aes128", pw: goodZipPW, field: "zip_encryption", msg: msgEnc},
		{name: "method case", mode: "zip", enc: "AES256", pw: goodZipPW, field: "zip_encryption", msg: msgEnc},
		{name: "unknown method before password", mode: "zip", enc: "none", field: "zip_encryption", msg: msgEnc},
		{name: "legacy off", mode: "zip", enc: "zipcrypto", pw: goodZipPW,
			set: []setting{{SettingZipLegacyEncryption, false}}, field: "zip_encryption", msg: msgLegacy},
		{name: "legacy off, aes256", mode: "zip", enc: "aes256", pw: goodZipPW,
			set: []setting{{SettingZipLegacyEncryption, false}}, want: core.ZipEncAES256},
		{name: "method without password", mode: "zip", enc: "aes256", field: "zip_password", msg: msgEmpty},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, s := range c.set {
				f.Settings.Put(s.key, s.val)
			}
			defer func() {
				f.Settings.Put(SettingZipPasswordMin, DefaultZipPasswordMin)
				f.Settings.Put(SettingZipLegacyEncryption, DefaultZipLegacyEncryption)
			}()
			actor := a
			if c.actor != nil {
				actor = *c.actor
			}
			before := f.Int(`SELECT COUNT(*) FROM upload_batches`)
			in := core.BatchInput{FolderID: f.aliceRoot, Mode: c.mode, ZipEncryption: c.enc, ZipPassword: core.Secret(c.pw),
				Files: []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}}}
			if c.actor != nil {
				in.FolderID = ""
			}
			b, err := f.svc.CreateBatch(f.ctx, actor, in)
			if c.field == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if b.ZipEncryption != c.want {
					t.Fatalf("zip_encryption %q, want %q", b.ZipEncryption, c.want)
				}
				if got := f.Str(`SELECT zip_encryption FROM upload_batches WHERE id = ?`, b.ID); got != c.want {
					t.Fatalf("stored zip_encryption %q", got)
				}
				if sealed := f.sealedPW(b.ID); (sealed != "") != (c.want != "") {
					t.Fatalf("sealed password %q for encryption %q", sealed, c.want)
				}
				if err := f.svc.AbortBatch(f.ctx, actor, b.ID); err != nil { // keep under the open-batch cap
					t.Fatal(err)
				}
				return
			}
			ce := core.AsError(err)
			if ce == nil || ce.Code != core.ErrInvalid.Code || ce.Field != c.field || ce.Message != c.msg {
				t.Fatalf("got %v, want 422 %s: %q", err, c.field, c.msg)
			}
			if len(c.pw) >= 4 && strings.Contains(err.Error(), c.pw) {
				t.Fatalf("the error contains the password: %v", err)
			}
			if after := f.Int(`SELECT COUNT(*) FROM upload_batches`); after != before {
				t.Fatalf("a refused batch was recorded (%d → %d rows)", before, after)
			}
		})
	}
}

// memLogger returns a logger writing through a text and a JSON handler
// (debug level) into buf.
func memLogger(buf *syncBuffer) *slog.Logger {
	o := &slog.HandlerOptions{Level: slog.LevelDebug}
	return slog.New(slog.NewMultiHandler(slog.NewTextHandler(buf, o), slog.NewJSONHandler(buf, o)))
}

// syncBuffer is a bytes.Buffer safe for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestZipPasswordSealedAtRest pins where the password lives: sealed in
// upload_batches.zip_password_enc (bound to the batch id) while the batch
// is open or finalizing, and nowhere else in clear.
func TestZipPasswordSealedAtRest(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	var logs syncBuffer
	f.svc.log = memLogger(&logs)
	evs, unsub := f.Bus.Subscribe()
	defer unsub()
	a := f.actor(f.alice)
	marker := "Zp-" + ids.Token(16)
	pw := marker + " #7"
	entries := []zipEntry{{rel: "notes/a.txt", data: []byte("hello, fileparcel")}, {rel: "notes", dir: true}}

	in := core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip, ZipName: "Secret",
		ZipPassword: core.Secret(pw), Files: []core.UploadFileInput{
			{ClientRef: "a", RelPath: "notes/a.txt", Size: int64(len(entries[0].data)), MTime: testMtime}}}
	created, err := f.svc.CreateBatch(f.ctx, a, in)
	if err != nil {
		t.Fatal(err)
	}
	other := f.protectedBatch(a, "Other", "", goodZipPW, nil)
	var seen []string // every text the password must not appear in
	add := func(what string, v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		seen = append(seen, what+": "+string(raw))
	}
	add("CreateBatch", created)

	// Sealed with the field key, bound to the batch.
	sealed := f.sealedPW(created.ID)
	if !strings.HasPrefix(sealed, "v1:") || strings.Contains(sealed, marker) {
		t.Fatalf("sealed value %q", sealed)
	}
	if got, err := f.Keys.OpenField(zipPasswordAAD(created.ID), sealed); err != nil || string(got) != pw {
		t.Fatalf("OpenField: %q %v", got, err)
	}
	if _, err := f.Keys.OpenField(zipPasswordAAD(other.ID), sealed); err == nil {
		t.Fatal("the sealed value opens with another batch's AAD")
	}
	if _, err := f.Keys.OpenField(zipPasswordAAD(created.ID), f.sealedPW(other.ID)); err == nil {
		t.Fatal("another batch's sealed value opens with this batch's AAD")
	}

	f.sendAll(a, created, entries)
	got, err := f.svc.GetBatch(f.ctx, a, created.ID)
	if err != nil || got.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("GetBatch: %+v %v", got, err)
	}
	add("GetBatch open", got)
	fin, err := f.runZip(a, created)
	if err != nil {
		t.Fatalf("zip job: %v", err)
	}
	job, _ := f.Jobs.Get(f.ctx, fin.JobID)
	add("job", job)
	if got, err = f.svc.GetBatch(f.ctx, a, created.ID); err != nil || got.State != core.BatchDone {
		t.Fatalf("GetBatch done: %+v %v", got, err)
	}
	add("GetBatch done", got)
	for _, e := range f.Audit.Entries {
		add("audit "+e.Action, e)
	}

	// Logging the input itself (text and JSON handlers, fmt verbs).
	f.svc.log.Info("input", slog.Any("in", in))
	f.svc.log.Info("input value", "in", in)
	seen = append(seen, fmt.Sprintf("%v %+v %#v %s %q", in, in, in, in.ZipPassword, in.ZipPassword))
	seen = append(seen, "logs: "+logs.String())
	if !strings.Contains(logs.String(), "zip_password_set") || !strings.Contains(logs.String(), "upload batch created") {
		t.Fatalf("the logs are not captured: %s", logs.String())
	}

	// Every bus event (the service published several meanwhile).
	unsub()
	var topics []string
	for ev := range evs {
		add("event "+ev.Topic, ev.Data)
		topics = append(topics, ev.Topic)
	}
	if !slices.Contains(topics, events.TopicUploadBatchDone) {
		t.Fatalf("events %v lack %s", topics, events.TopicUploadBatchDone)
	}
	for _, s := range seen {
		if strings.Contains(s, marker) {
			t.Fatalf("the password appears in %s", s)
		}
	}
	if sealed := f.sealedPW(created.ID); sealed != "" {
		t.Fatalf("a finished batch keeps its sealed password %q", sealed)
	}

	// The database file and its WAL, before and after a checkpoint.
	scan := func(when string) {
		for _, p := range []string{f.Env.Env.Home.DB(), f.Env.Env.Home.DB() + "-wal"} {
			raw, err := os.ReadFile(p)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(marker)) {
				t.Fatalf("%s: the password is in %s", when, p)
			}
		}
	}
	scan("before the checkpoint")
	var busy, logPages, ckPages int
	if err := f.DB.Writer().QueryRowContext(f.ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logPages, &ckPages); err != nil || busy != 0 {
		t.Fatalf("checkpoint: busy %d, %v", busy, err)
	}
	scan("after the checkpoint")
}

// TestZipPasswordJobProducesProtectedZip runs whole protected uploads (AES
// and ZipCrypto) and reads the result with the independent test reader.
func TestZipPasswordJobProducesProtectedZip(t *testing.T) {
	fox := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog\n"), 2000)
	entries := []zipEntry{
		{rel: "docs", dir: true},
		{rel: "docs/fox.txt", data: fox},
		{rel: "docs/rand.bin", data: content(70_000, 21)},
		{rel: "photo.jpg", data: content(40_000, 22)},
		{rel: "big.bin", data: content(core.PartSize+4096, 23)},
		{rel: "empty.txt", data: []byte{}},
		{rel: "café über.txt", data: []byte("é")},
	}
	for _, enc := range []string{core.ZipEncAES256, core.ZipEncZipCrypto} {
		t.Run(enc, func(t *testing.T) {
			f := setup(t)
			f.Jobs.Manual = true
			done, unsub := f.Bus.Subscribe(events.TopicUploadBatchDone)
			defer unsub()
			a := f.actor(f.alice)
			b := f.protectedBatch(a, "Protected", enc, goodZipPW, entries)
			if b.ZipEncryption != enc {
				t.Fatalf("batch zip_encryption %q", b.ZipEncryption)
			}
			f.sendAll(a, b, entries)
			fin, err := f.runZip(a, b)
			if err != nil {
				t.Fatalf("zip job: %v", err)
			}
			data, node := f.nodeContent(f.aliceRoot, "Protected.zip")
			if node.ZipEncryption != enc {
				t.Fatalf("node zip_encryption %q", node.ZipEncryption)
			}
			if got := f.Str(`SELECT zip_encryption FROM file_versions WHERE id = ?`, node.VersionID); got != enc {
				t.Fatalf("version zip_encryption %q", got)
			}
			got, err := ziputiltest.ReadBytes(data, goodZipPW)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			want := map[string]zipEntry{}
			for _, e := range entries {
				want[e.rel] = e
			}
			if len(got) != len(entries) {
				t.Fatalf("%d entries, want %d", len(got), len(entries))
			}
			for _, e := range got {
				w, ok := want[strings.TrimSuffix(e.Name, "/")]
				switch {
				case !ok:
					t.Fatalf("unexpected entry %q", e.Name)
				case w.dir:
					if !e.Dir || e.Encryption != "" {
						t.Errorf("%s: dir %v, encryption %q", e.Name, e.Dir, e.Encryption)
					}
				default:
					if e.Encryption != enc || !bytes.Equal(e.Data, w.data) {
						t.Errorf("%s: encryption %q, %d bytes (want %d)", e.Name, e.Encryption, len(e.Data), len(w.data))
					}
					if e.Modified.Unix() != testMtime/1000 {
						t.Errorf("%s: modified %v", e.Name, e.Modified)
					}
				}
			}
			if _, err := ziputiltest.ReadBytes(data, "wrong password 1"); !errors.Is(err, ziputiltest.ErrWrongPassword) &&
				!errors.Is(err, ziputiltest.ErrAuthFailed) && !errors.Is(err, ziputiltest.ErrCRC) {
				t.Fatalf("wrong password: %v", err)
			}

			// The job: params are the batch id only, the result names the
			// encryption, the password is gone.
			job, _ := f.Jobs.Get(f.ctx, fin.JobID)
			if string(job.Params) != `{"batch_id":"`+b.ID+`"}` {
				t.Fatalf("job params %s", job.Params)
			}
			var res zipResult
			if err := json.Unmarshal(job.Result, &res); err != nil || res.Encryption != enc || res.NodeID != node.ID ||
				res.Files != 6 {
				t.Fatalf("job result %s (%v)", job.Result, err)
			}
			if n := f.Int(`SELECT COUNT(*) FROM upload_batches WHERE id = ? AND zip_password_enc IS NULL AND state = 'done'`, b.ID); n != 1 {
				t.Fatal("the finished batch keeps its password")
			}
			select {
			case ev := <-done:
				if got := ev.Data.(core.UploadBatchEvent).Batch; got.ZipEncryption != enc || got.State != core.BatchDone {
					t.Fatalf("event batch %+v", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no upload.batch_done")
			}
		})
	}
}

// TestZipPasswordWiped pins that every transition out of open/finalizing
// wipes the sealed password, and that the one step back to open keeps it.
func TestZipPasswordWiped(t *testing.T) {
	one := []zipEntry{{rel: "a.txt", data: []byte("a")}}
	start := func(t *testing.T) (*fixture, core.UploadActor, *core.UploadBatch) {
		f := setup(t)
		f.Jobs.Manual = true
		a := f.actor(f.alice)
		b := f.protectedBatch(a, "Wipe", "", goodZipPW, one)
		f.sendAll(a, b, one)
		if f.sealedPW(b.ID) == "" {
			t.Fatal("no sealed password")
		}
		return f, a, b
	}
	wantWiped := func(t *testing.T, f *fixture, id, state string) {
		t.Helper()
		if st := f.batchState(id); st != state {
			t.Fatalf("state %s, want %s", st, state)
		}
		if s := f.sealedPW(id); s != "" {
			t.Fatalf("%s batch keeps its password %q", state, s)
		}
	}

	t.Run("abort", func(t *testing.T) {
		f, a, b := start(t)
		if err := f.svc.AbortBatch(f.ctx, a, b.ID); err != nil {
			t.Fatal(err)
		}
		wantWiped(t, f, b.ID, core.BatchAborted)
	})
	t.Run("expire", func(t *testing.T) {
		f, _, b := start(t)
		f.Clock.Advance(DefaultExpiryHours*time.Hour + time.Minute)
		if n, err := f.svc.ExpireStale(f.ctx); err != nil || n != 1 {
			t.Fatalf("expired %d, %v", n, err)
		}
		wantWiped(t, f, b.ID, core.BatchExpired)
	})
	t.Run("job failure", func(t *testing.T) {
		f, a, b := start(t)
		fin := f.complete(a, b.ID)
		blob := f.Str(`SELECT blob_id FROM upload_files WHERE batch_id = ?`, b.ID)
		if err := f.Blobs.Delete(f.ctx, blob); err != nil {
			t.Fatal(err)
		}
		if err := f.Jobs.Run(fin.JobID); err == nil {
			t.Fatal("the job succeeded without its data")
		}
		wantWiped(t, f, b.ID, core.BatchFailed)
		e, ok := f.Audit.Find(core.ActFileUpload)
		if d, _ := e.Details.(map[string]any); !ok || e.Outcome != core.OutcomeFailure || d["zip_encryption"] != core.ZipEncAES256 {
			t.Fatalf("failure audit %+v", e)
		}
	})
	t.Run("job cancelled", func(t *testing.T) {
		f, a, b := start(t)
		fin := f.complete(a, b.ID)
		f.Jobs.SetState(fin.JobID, core.JobCanceled)
		if _, err := f.svc.ExpireStale(f.ctx); err != nil {
			t.Fatal(err)
		}
		wantWiped(t, f, b.ID, core.BatchFailed)
	})
	t.Run("stuck past the retry bound", func(t *testing.T) {
		f, a, b := start(t)
		fin := f.complete(a, b.ID)
		f.Jobs.SetState(fin.JobID, core.JobFailed)
		f.Clock.Advance(DefaultExpiryHours*time.Hour + time.Minute)
		if _, err := f.svc.ExpireStale(f.ctx); err != nil {
			t.Fatal(err)
		}
		wantWiped(t, f, b.ID, core.BatchFailed)
	})
	t.Run("interrupted job keeps it for the re-run", func(t *testing.T) {
		f, a, b := start(t)
		fin := f.complete(a, b.ID)
		f.Jobs.SetState(fin.JobID, core.JobFailed)
		if _, err := f.svc.ExpireStale(f.ctx); err != nil {
			t.Fatal(err)
		}
		rerun := f.Str(`SELECT job_id FROM upload_batches WHERE id = ?`, b.ID)
		if rerun == fin.JobID || f.sealedPW(b.ID) == "" || f.batchState(b.ID) != core.BatchFinalizing {
			t.Fatalf("re-run %q, state %s", rerun, f.batchState(b.ID))
		}
		if err := f.Jobs.Run(rerun); err != nil {
			t.Fatal(err)
		}
		wantWiped(t, f, b.ID, core.BatchDone)
		data, _ := f.nodeContent(f.aliceRoot, "Wipe.zip")
		if got, err := ziputiltest.ReadBytes(data, goodZipPW); err != nil || len(got) != 1 || string(got[0].Data) != "a" {
			t.Fatalf("re-run zip: %+v %v", got, err)
		}
	})
	t.Run("sweep", func(t *testing.T) {
		f, a, b := start(t)
		if _, err := f.runZip(a, b); err != nil {
			t.Fatal(err)
		}
		f.Exec(`UPDATE upload_batches SET zip_password_enc = 'v1:x' WHERE id = ?`, b.ID)
		open := f.protectedBatch(a, "Still open", "", goodZipPW, one)
		if _, err := f.svc.ExpireStale(f.ctx); err != nil {
			t.Fatal(err)
		}
		wantWiped(t, f, b.ID, core.BatchDone)
		if f.sealedPW(open.ID) == "" {
			t.Fatal("the sweep wiped an open batch")
		}
	})
	t.Run("enqueue error keeps it", func(t *testing.T) {
		f, a, b := start(t)
		f.svc.jobs = failingEnqueue{f.Jobs}
		if _, err := f.svc.CompleteBatch(f.ctx, a, b.ID); !errors.Is(err, core.ErrUnavailable) {
			t.Fatalf("complete: %v", err)
		}
		if st := f.batchState(b.ID); st != core.BatchOpen || f.sealedPW(b.ID) == "" {
			t.Fatalf("state %s, sealed %q", st, f.sealedPW(b.ID))
		}
		f.svc.jobs = f.Jobs
		if _, err := f.runZip(a, b); err != nil {
			t.Fatal(err)
		}
		wantWiped(t, f, b.ID, core.BatchDone)
	})
}

// failingEnqueue is a job runner whose queue refuses new jobs.
type failingEnqueue struct{ *uploadtest.Jobs }

func (failingEnqueue) Enqueue(context.Context, string, any, *core.Principal) (string, error) {
	return "", core.Wrap(core.ErrUnavailable, "the job queue is full", nil)
}

// TestStartZipFailsFastWhenUnopenable pins that completing a protected
// batch whose password cannot be used is refused while the batch is still
// open, before any job runs or data is deleted.
func TestStartZipFailsFastWhenUnopenable(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	one := []zipEntry{{rel: "a.txt", data: []byte("a")}}
	b := f.protectedBatch(a, "Fast", "", goodZipPW, one)
	other := f.protectedBatch(a, "Other", "", goodZipPW, one)
	f.sendAll(a, b, one)
	sealed := f.sealedPW(b.ID)
	check := func(what string, want *core.Error) {
		t.Helper()
		_, err := f.svc.CompleteBatch(f.ctx, a, b.ID)
		if !errors.Is(err, want) {
			t.Fatalf("%s: %v, want %s", what, err, want.Code)
		}
		if st := f.batchState(b.ID); st != core.BatchOpen {
			t.Fatalf("%s: state %s", what, st)
		}
		if job := f.Str(`SELECT job_id FROM upload_batches WHERE id = ?`, b.ID); job != "" {
			t.Fatalf("%s: a job was enqueued", what)
		}
		if n := f.Int(`SELECT COUNT(*) FROM upload_files WHERE batch_id = ? AND blob_id IS NOT NULL`, b.ID); n != 1 {
			t.Fatalf("%s: staged data gone", what)
		}
	}
	f.Exec(`UPDATE upload_batches SET zip_password_enc = 'v1:kek_test:00ff' WHERE id = ?`, b.ID)
	check("corrupted", core.ErrCorrupt)
	f.Exec(`UPDATE upload_batches SET zip_password_enc = ? WHERE id = ?`, f.sealedPW(other.ID), b.ID)
	check("another batch's value", core.ErrCorrupt)
	f.Exec(`UPDATE upload_batches SET zip_password_enc = NULL WHERE id = ?`, b.ID)
	check("wiped", core.ErrPrecondition)
	f.Exec(`UPDATE upload_batches SET zip_password_enc = ? WHERE id = ?`, sealed, b.ID)
	f.Keys.Locked.Store(true)
	check("keys locked", core.ErrKeysLocked)
	f.Keys.Locked.Store(false)
	if _, err := f.runZip(a, b); err != nil {
		t.Fatal(err)
	}
	if st := f.batchState(b.ID); st != core.BatchDone {
		t.Fatalf("state %s", st)
	}
	// A new protected batch cannot even be created while the keys are locked.
	f.Keys.Locked.Store(true)
	_, err := f.svc.CreateBatch(f.ctx, a, core.BatchInput{FolderID: f.aliceRoot, Mode: core.UploadModeZip,
		ZipPassword: goodZipPW})
	if !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("create while locked: %v", err)
	}
}

// TestZipJobKeysLocked pins that locked keys postpone the job instead of
// failing the batch: its data and sealed password stay for the re-run.
func TestZipJobKeysLocked(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	one := []zipEntry{{rel: "a.txt", data: []byte("a")}}
	b := f.protectedBatch(a, "Later", "", goodZipPW, one)
	f.sendAll(a, b, one)
	fin := f.complete(a, b.ID)
	f.Keys.Locked.Store(true)
	if err := f.Jobs.Run(fin.JobID); !errors.Is(err, core.ErrKeysLocked) {
		t.Fatalf("job: %v", err)
	}
	if st := f.batchState(b.ID); st != core.BatchFinalizing || f.sealedPW(b.ID) == "" || f.Blobs.Count() != 1 {
		t.Fatalf("state %s, sealed %q, blobs %d", st, f.sealedPW(b.ID), f.Blobs.Count())
	}
	f.Keys.Locked.Store(false)
	if _, err := f.svc.ExpireStale(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.Jobs.Run(f.Str(`SELECT job_id FROM upload_batches WHERE id = ?`, b.ID)); err != nil {
		t.Fatal(err)
	}
	if st := f.batchState(b.ID); st != core.BatchDone || f.sealedPW(b.ID) != "" {
		t.Fatalf("after the re-run: state %s", st)
	}
}

// TestProtectedZipWithoutFiles: a protected batch of folders only has no
// entry to encrypt, so neither the node nor the job result claim a password.
func TestProtectedZipWithoutFiles(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	entries := []zipEntry{{rel: "a", dir: true}, {rel: "a/b", dir: true}}
	b := f.protectedBatch(a, "Folders", core.ZipEncAES256, goodZipPW, entries)
	if b.ZipEncryption != core.ZipEncAES256 {
		t.Fatalf("batch %q", b.ZipEncryption)
	}
	fin, err := f.runZip(a, b)
	if err != nil {
		t.Fatal(err)
	}
	data, node := f.nodeContent(f.aliceRoot, "Folders.zip")
	if node.ZipEncryption != "" {
		t.Fatalf("node zip_encryption %q", node.ZipEncryption)
	}
	got, err := ziputiltest.ReadBytes(data, "")
	if err != nil || len(got) != 2 {
		t.Fatalf("read without a password: %+v %v", got, err)
	}
	for _, e := range got {
		if !e.Dir || e.Encryption != "" {
			t.Fatalf("entry %+v", e)
		}
	}
	job, _ := f.Jobs.Get(f.ctx, fin.JobID)
	if strings.Contains(string(job.Result), "encryption") {
		t.Fatalf("job result %s", job.Result)
	}
	if f.sealedPW(b.ID) != "" {
		t.Fatal("password kept")
	}
}

// TestZipJobCancelMidEntry pins that a cancelled job stops inside a long
// entry: the blob is not read again once the context is done.
func TestZipJobCancelMidEntry(t *testing.T) {
	for _, pw := range []string{"", goodZipPW} {
		t.Run(fmt.Sprintf("protected=%v", pw != ""), func(t *testing.T) {
			f := setup(t)
			f.Jobs.Manual = true
			a := f.actor(f.alice)
			entries := []zipEntry{{rel: "big.bin", data: content(20<<20, 31)}}
			b := f.protectedBatch(a, "Big", "", pw, entries)
			f.sendAll(a, b, entries)
			fin := f.complete(a, b.ID)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			var mu sync.Mutex
			reads, afterCancel := 0, 0
			f.Blobs.ReadHook = func(_ string, off int64) {
				mu.Lock()
				defer mu.Unlock()
				reads++
				if ctx.Err() != nil {
					afterCancel++
				}
				if off >= 1<<20 {
					cancel()
				}
			}
			start := time.Now()
			if err := f.svc.zipBatch(ctx, nopHandle{}, b.ID); !errors.Is(err, context.Canceled) {
				t.Fatalf("zipBatch = %v", err)
			}
			mu.Lock()
			if afterCancel > 1 || reads == 0 {
				t.Errorf("%d reads, %d after the cancel", reads, afterCancel)
			}
			mu.Unlock()
			if d := time.Since(start); d > 10*time.Second {
				t.Errorf("the cancelled job took %v", d)
			}
			// As after any cancel: maintenance.uploads fails the batch.
			if st := f.batchState(b.ID); st != core.BatchFinalizing {
				t.Fatalf("state %s", st)
			}
			f.Jobs.SetState(fin.JobID, core.JobCanceled)
			if _, err := f.svc.ExpireStale(f.ctx); err != nil {
				t.Fatal(err)
			}
			if st := f.batchState(b.ID); st != core.BatchFailed || f.sealedPW(b.ID) != "" {
				t.Fatalf("after maintenance: state %s", st)
			}
		})
	}
}

// TestZipJobUnprotectedParity pins that the job's switch to AddFileAt (with
// the cancellable reader) left unprotected zips byte for byte as AddFile
// wrote them.
func TestZipJobUnprotectedParity(t *testing.T) {
	f := setup(t)
	f.Jobs.Manual = true
	a := f.actor(f.alice)
	entries := []zipEntry{
		{rel: "b/text.txt", data: bytes.Repeat([]byte("parity "), 5000)},
		{rel: "a.jpg", data: content(30_000, 41)},
		{rel: "b", dir: true},
		{rel: "b/c", dir: true},
		{rel: "big.bin", data: content(core.PartSize+10, 42)},
		{rel: "empty", data: []byte{}},
	}
	b := f.protectedBatch(a, "Plain", "", "", entries)
	f.sendAll(a, b, entries)
	if _, err := f.runZip(a, b); err != nil {
		t.Fatal(err)
	}
	got, node := f.nodeContent(f.aliceRoot, "Plain.zip")
	if node.ZipEncryption != "" {
		t.Fatalf("zip_encryption %q", node.ZipEncryption)
	}
	// The job's order: rel_path, then kind ("dir" before "file").
	sorted := append([]zipEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].rel != sorted[j].rel {
			return sorted[i].rel < sorted[j].rel
		}
		return sorted[i].dir && !sorted[j].dir
	})
	var want bytes.Buffer
	zw, err := ziputil.New(&want, ziputil.Options{Format: ziputil.FormatZip, Compression: f.svc.zipCompression()})
	if err != nil {
		t.Fatal(err)
	}
	mod := db.FromMs(testMtime)
	for _, e := range sorted {
		if e.dir {
			err = zw.AddDir(e.rel, mod)
		} else {
			err = zw.AddFile(e.rel, mod, int64(len(e.data)), bytes.NewReader(e.data))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("the job's zip (%d bytes) differs from AddFile's (%d bytes)", len(got), want.Len())
	}
}
