package uploads

import (
	"context"
	"strings"

	"fileparcel/internal/core"
	"fileparcel/internal/db"
	"fileparcel/internal/names"
)

// Existing names are looked up when files are declared (DESIGN §8.1), so
// that the conflict policies that do not store the new file find out before
// any byte is sent rather than after the whole upload (or the zip job):
//
//   - mode=files, conflict "skip": a file whose name is taken is declared
//     "skipped" (nothing reserved, nothing to send);
//   - mode=files, conflict "fail": a taken name refuses the declaration (409);
//   - mode=zip: "fail" on a taken zip_name and "replace" onto a folder of that
//     name refuse it (409); "skip" declares every file "skipped", and the
//     batch completes without building the .zip.
//
// The node commit still applies the policy, so a name taken or freed in
// between is handled exactly as before.

// maxNumberedDirs bounds the "name (n)" folders followed while resolving a
// path (files.maxNumbered).
const maxNumberedDirs = 10_000

// taken is a live node holding a name.
type taken struct{ id, name, kind string }

// nameCheck resolves declared paths against the destination folder the way
// files.CommitFile will commit them.
type nameCheck struct {
	ctx  context.Context
	q    querier
	root string
	dirs map[string]string // rel folder path → folder id ("" = does not exist yet)
}

func newNameCheck(ctx context.Context, q querier, root string) *nameCheck {
	return &nameCheck{ctx: ctx, q: q, root: root, dirs: map[string]string{}}
}

// child returns the live node of folder parentID with the name key key.
func (c *nameCheck) child(parentID, key string) (*taken, error) {
	var t taken
	err := c.q.QueryRowContext(c.ctx, `SELECT id, name, kind FROM nodes
		WHERE parent_id = ? AND name_key = ? AND trashed_at IS NULL`, parentID, key).Scan(&t.id, &t.name, &t.kind)
	if db.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// folder returns the folder that the path segs (below the destination)
// resolves to, or "" when it does not exist yet. As files.CommitFile
// creates missing folders, a file holding a folder's name moves the folder
// to "name (1)", "name (2)", …
func (c *nameCheck) folder(segs []string) (string, error) {
	if len(segs) == 0 {
		return c.root, nil
	}
	k := strings.Join(segs, "/")
	if id, ok := c.dirs[k]; ok {
		return id, nil
	}
	parent, err := c.folder(segs[:len(segs)-1])
	if err != nil {
		return "", err
	}
	id := ""
	if parent != "" {
		name := segs[len(segs)-1]
		for n := 0; n <= maxNumberedDirs; n++ {
			t, err := c.child(parent, names.Key(names.Numbered(name, n, true)))
			if err != nil {
				return "", err
			}
			if t == nil {
				break // created at commit
			}
			if t.kind == core.KindFolder {
				id = t.id
				break
			}
		}
	}
	c.dirs[k] = id
	return id, nil
}

// target returns the node that holds relPath now (nil when none).
func (c *nameCheck) target(relPath string) (*taken, error) {
	segs := strings.Split(relPath, "/")
	dir, err := c.folder(segs[:len(segs)-1])
	if err != nil || dir == "" {
		return nil, err
	}
	return c.child(dir, names.Key(segs[len(segs)-1]))
}

// preflight applies the declaration-time checks above to the entries of
// batch b and marks the entries to declare "skipped". For a mode=zip batch
// it reports whether the .zip is skipped; an AddFiles call passes
// zipSkipped for a batch that already skips it.
func (svc *Service) preflight(ctx context.Context, b *core.UploadBatch, entries []entry, zipSkipped bool) (bool, error) {
	switch {
	case b.ShareID != "": // file requests always rename
		return false, nil
	case b.Mode == core.UploadModeZip:
		skip := zipSkipped
		if !skip && b.Conflict != core.ConflictRename {
			t, err := newNameCheck(ctx, svc.env.DB.Reader(), b.FolderID).target(b.ZipName)
			if err != nil {
				return false, err
			}
			switch {
			case t == nil:
			case b.Conflict == core.ConflictFail:
				return false, core.Errorf(core.ErrConflict, "“%s” already exists in this folder", t.name)
			case b.Conflict == core.ConflictSkip:
				skip = true
			case b.Conflict == core.ConflictReplace && t.kind != core.KindFile:
				return false, core.Errorf(core.ErrConflict, "“%s” is a folder and cannot be replaced by a file", t.name)
			}
		}
		if skip {
			for i := range entries {
				if entries[i].kind == core.UploadKindFile {
					entries[i].skipped = true
				}
			}
		}
		return skip, nil
	case b.Conflict != core.ConflictSkip && b.Conflict != core.ConflictFail:
		return false, nil
	}
	check := newNameCheck(ctx, svc.env.DB.Reader(), b.FolderID)
	for i := range entries {
		e := &entries[i]
		if e.kind != core.UploadKindFile {
			continue
		}
		t, err := check.target(e.relPath)
		if err != nil {
			return false, err
		}
		if t == nil {
			continue
		}
		if b.Conflict == core.ConflictFail {
			return false, core.Errorf(core.ErrConflict, "“%s” already exists in this folder", e.relPath)
		}
		e.skipped = true
	}
	return false, nil
}

// sendBytes returns the declared bytes of the files that will be sent (not
// declared skipped).
func sendBytes(entries []entry) int64 {
	var n int64
	for _, e := range entries {
		if e.kind == core.UploadKindFile && !e.skipped {
			n += e.size
		}
	}
	return n
}
