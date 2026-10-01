package sharesapi

import (
	"encoding/json"
	"strings"
	"testing"

	"fileparcel/internal/core"
)

// When the creator of a share can no longer add files to its folder, a file
// request stops resolving (the visitor gets the page of a request that is
// gone, not a form whose every upload fails), and a link that accepts
// uploads refuses them as "does not accept uploads" — never with the
// creator's permission error, which names the folder.
func TestUploadsWhenCreatorLostEdit(t *testing.T) {
	f := setup(t)
	projects := f.Mkdir(f.bobRt, "Projects")
	f.Files.Grant(f.alice, projects, core.PermManage)
	_, reqTok := f.share(f.alice, core.ShareInput{Kind: core.ShareRequest, NodeID: projects})
	_, linkTok := f.share(f.alice, core.ShareInput{NodeID: projects, AllowUpload: true})
	files := []core.UploadFileInput{{ClientRef: "a", RelPath: "a.txt", Size: 1}}
	f.do(req{method: "GET", path: "/s/" + reqTok + "/api"}).json(t, &core.PublicShareInfo{})

	f.Files.Grant(f.alice, projects, core.PermView)
	f.do(req{method: "GET", path: "/s/" + reqTok + "/api"}).wantErr(t, 404, "not_found")
	f.do(req{method: "POST", path: "/s/" + reqTok + "/api/upload-batches", json: core.BatchInput{Files: files}}).
		wantErr(t, 404, "not_found")
	r := f.do(req{method: "POST", path: "/s/" + linkTok + "/api/upload-batches", json: core.BatchInput{Files: files}})
	r.wantErr(t, 403, "forbidden")
	var e apiErr
	_ = json.Unmarshal(r.body, &e)
	if e.Error.Message != "this share does not accept uploads" || strings.Contains(string(r.body), "Projects") {
		t.Fatalf("link upload refusal: %s", r.body)
	}
	// Downloads through the link keep working for a viewer.
	f.do(req{method: "GET", path: "/s/" + linkTok + "/api"}).json(t, &core.PublicShareInfo{})
}
