package names

import (
	"strings"
	"testing"
)

func TestMIMEFromName(t *testing.T) {
	cases := map[string]string{
		"a.PNG":          "image/png",
		"photo.jpeg":     "image/jpeg",
		"x.svg":          "image/svg+xml",
		"doc.pdf":        "application/pdf",
		"notes.md":       "text/markdown",
		"main.go":        "text/x-go",
		"index.html":     "text/html",
		"app.js":         "text/javascript",
		"data.json":      "application/json",
		"archive.tar.gz": "application/gzip",
		"noext":          "",
		"trailing.":      "",
		".bashrc":        "", // path.Ext(".bashrc") = ".bashrc": unknown
	}
	for in, want := range cases {
		if got := MIMEFromName(in); got != want {
			t.Errorf("MIMEFromName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBaseMIME(t *testing.T) {
	cases := map[string]string{
		"Text/HTML; charset=UTF-8": "text/html",
		"image/png":                "image/png",
		"":                         "",
		"garbage":                  "",
		"a/b/c":                    "",
		";;":                       "",
	}
	for in, want := range cases {
		if got := BaseMIME(in); got != want {
			t.Errorf("BaseMIME(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetectMIME(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	jpeg := []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00")
	pdf := []byte("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	html := []byte("<!DOCTYPE html><html><script>alert(1)</script></html>")
	text := []byte("just some text\n")
	bin := []byte{0x00, 0x01, 0x02, 0x03, 0xfe, 0xff, 0x10, 0x00}
	cases := []struct {
		name, hint string
		head       []byte
		want       string
	}{
		{"a.png", "", png, "image/png"},
		{"a.png", "", jpeg, "image/png"},        // same family: extension wins
		{"a.png", "", html, "text/html"},        // HTML named .png: the sniff wins
		{"a.jpg", "", text, "text/plain"},       // text named .jpg
		{"a.avif", "", bin, "image/avif"},       // opaque binary: keep the name's type
		{"doc.pdf", "", pdf, "application/pdf"}, //
		{"doc.pdf", "", html, "text/html"},      // a PDF must really be a PDF
		{"doc.pdf", "", bin, OctetStream},       //
		{"doc.pdf", "", nil, "application/pdf"}, // unreadable: keep the name's type
		{"clip.mp4", "", html, "text/html"},     //
		{"clip.mp4", "", png, "image/png"},      // a different media family
		{"song.ogg", "", []byte("OggS\x00\x02"), "audio/ogg"},
		{"evil.html", "", html, "text/html"}, // markup stays markup (attachment)
		{"evil.svg", "", []byte("<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>"), "image/svg+xml"},
		{"script.ts", "", []byte("export const x: number = 1;\n"), "text/plain"}, // TypeScript, not MPEG-TS
		{"readme.txt", "", html, "text/plain"},                                   // text claims are kept (served as text/plain)
		{"noext", "", png, "image/png"},                                          // unknown name: the sniff decides
		{"noext", "image/gif", nil, "image/gif"},                                 // unknown name, unreadable: the hint
		{"noext", "application/octet-stream", text, "text/plain"},
		{"noext", "", nil, OctetStream},
		{"empty", "", []byte{}, "text/plain"},
		{"empty.png", "", []byte{}, "image/png"},
		{"big.bin", "", append(png, make([]byte, 4096)...), "application/octet-stream"}, // .bin → mime.TypeByExtension
	}
	for _, c := range cases {
		got := DetectMIME(c.name, c.hint, c.head)
		if c.name == "big.bin" {
			// mime.TypeByExtension(".bin") depends on the host tables; only
			// require a non-inline answer.
			if strings.HasPrefix(got, "image/") {
				t.Errorf("DetectMIME(big.bin) = %q", got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("DetectMIME(%q, %q, %q) = %q, want %q", c.name, c.hint, c.head, got, c.want)
		}
	}
}
