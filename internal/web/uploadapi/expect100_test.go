package uploadapi

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/core"
)

// TestPartRejectedBeforeTheBody pins the part-upload contract of DESIGN §8.1:
// a wrong length, a bad part number, a malformed digest and an unknown upload
// are all decided from the request headers, before a byte of the body is
// read.
//
// That is what makes `Expect: 100-continue` useful here. A client that sends
// it gets "100 Continue" when the headers are acceptable and the final error
// instead when they are not — so a wrong-length part is answered with
// "part 2 must be exactly 77 bytes (got 8388608)" rather than cutting the
// client off mid-upload with a TCP reset it cannot interpret. The test drives
// a raw connection and never sends a body, so a handler that started reading
// before validating would show up as a missing early answer.
func TestPartRejectedBeforeTheBody(t *testing.T) {
	f := setup(t)
	big := data(2*core.PartSize + 77)
	var b core.UploadBatch
	f.json("POST", "/api/v1/upload-batches", f.alice, core.BatchInput{FolderID: f.root, Files: []core.UploadFileInput{
		{ClientRef: "big", RelPath: "big.bin", Size: int64(len(big))},
	}}, &b)
	if len(b.Files) != 1 || b.Files[0].PartCount != 3 {
		t.Fatalf("batch: %+v", b)
	}
	up := b.Files[0].ID

	u, err := url.Parse(f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	// head sends only the request head with Expect: 100-continue and reads the
	// server's first answer, without ever sending a body. 100 means "headers
	// accepted, send it"; anything else is the final response.
	head := func(path string, contentLength int, sha string) (int, string) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", u.Host, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		var h bytes.Buffer
		fmt.Fprintf(&h, "PUT %s HTTP/1.1\r\nHost: %s\r\n", path, u.Host)
		fmt.Fprintf(&h, "Authorization: Bearer %s\r\n", f.alice)
		fmt.Fprintf(&h, "Content-Type: application/octet-stream\r\n")
		fmt.Fprintf(&h, "Content-Length: %d\r\n", contentLength)
		fmt.Fprintf(&h, "%s: %s\r\n", HeaderSHA256, sha)
		fmt.Fprintf(&h, "Expect: 100-continue\r\nConnection: close\r\n\r\n")
		if _, err := conn.Write(h.Bytes()); err != nil {
			t.Fatalf("write head: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "PUT"})
		if err != nil {
			return 0, "no answer: " + err.Error()
		}
		defer resp.Body.Close()
		var body bytes.Buffer
		_, _ = body.ReadFrom(resp.Body)
		return resp.StatusCode, strings.TrimSpace(body.String())
	}

	part := big[:core.PartSize]
	good := sum(part)
	lastLen := len(big) - 2*core.PartSize // 77

	// Acceptable headers: the server asks for the body and nothing else.
	if status, body := head("/api/v1/uploads/"+up+"/parts/0", core.PartSize, good); status != http.StatusContinue {
		t.Fatalf("valid part headers answered %d (%s), want 100 Continue", status, body)
	}

	for _, tc := range []struct {
		name          string
		path          string
		contentLength int
		sha           string
		wantStatus    int
		wantIn        string
	}{
		{"wrong length", "/api/v1/uploads/" + up + "/parts/2", core.PartSize, good, 422,
			fmt.Sprintf("part 2 must be exactly %d bytes (got %d)", lastLen, core.PartSize)},
		{"part number out of range", "/api/v1/uploads/" + up + "/parts/9", core.PartSize, good, 422,
			"part number must be between 0 and 2"},
		{"malformed digest", "/api/v1/uploads/" + up + "/parts/0", core.PartSize, "zz", 422,
			"64 hex characters"},
		{"unknown upload", "/api/v1/uploads/upf_nosuchupload/parts/0", core.PartSize, good, 404, ""},
	} {
		status, body := head(tc.path, tc.contentLength, tc.sha)
		switch {
		case status == http.StatusContinue:
			t.Errorf("%s: the server asked for the body instead of rejecting the headers", tc.name)
		case status != tc.wantStatus:
			t.Errorf("%s: status %d, want %d (%s)", tc.name, status, tc.wantStatus, body)
		case tc.wantIn != "" && !strings.Contains(body, tc.wantIn):
			t.Errorf("%s: %q does not explain the problem (want %q)", tc.name, body, tc.wantIn)
		}
	}

	// The same decisions hold on the ordinary path, where the client sends the
	// body straight away.
	if r := f.do("PUT", "/api/v1/uploads/"+up+"/parts/0", f.alice, bytes.NewReader(part),
		map[string]string{HeaderSHA256: good}, nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("valid part: %d", r.StatusCode)
	}
	f.wantErr(f.do("PUT", "/api/v1/uploads/"+up+"/parts/2", f.alice, bytes.NewReader(big[:16]),
		map[string]string{HeaderSHA256: sum(big[:16])}, nil), 422, "invalid")
}
