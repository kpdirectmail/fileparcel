package names

import (
	"mime"
	"net/http"
	"path"
	"strings"
)

// MIME detection (DESIGN §8.2): a node's type is derived from its name
// (built-in table, then mime.TypeByExtension) and verified against a sniff of
// the first 512 bytes of the content (http.DetectContentType). The stored
// type is later mapped to the delivered Content-Type by httpx.ContentType;
// DetectMIME only has to make sure that a name can never smuggle content into
// a type that browsers render inline (or, for PDF, render with a weaker CSP).

// OctetStream is the type of unknown binary content.
const OctetStream = "application/octet-stream"

// SniffLen is the number of leading content bytes DetectMIME looks at.
const SniffLen = 512

// builtinMIME is consulted before mime.TypeByExtension, whose answer depends
// on the host's mime.types files. Keys are lowercase extensions with the dot.
var builtinMIME = map[string]string{}

func init() {
	add := func(typ string, exts ...string) {
		for _, e := range exts {
			builtinMIME["."+e] = typ
		}
	}
	// Images.
	add("image/png", "png", "apng")
	add("image/jpeg", "jpg", "jpeg", "jpe", "jfif", "pjpeg", "pjp")
	add("image/gif", "gif")
	add("image/webp", "webp")
	add("image/avif", "avif")
	add("image/bmp", "bmp", "dib")
	add("image/x-icon", "ico", "cur")
	add("image/svg+xml", "svg", "svgz")
	add("image/tiff", "tif", "tiff")
	add("image/heic", "heic")
	add("image/heif", "heif")
	add("image/jxl", "jxl")
	add("image/vnd.adobe.photoshop", "psd")
	// Video.
	add("video/mp4", "mp4", "m4v")
	add("video/quicktime", "mov", "qt")
	add("video/webm", "webm")
	add("video/ogg", "ogv")
	add("video/x-matroska", "mkv")
	add("video/x-msvideo", "avi")
	add("video/x-ms-wmv", "wmv")
	add("video/mpeg", "mpeg", "mpg", "mpe")
	add("video/mp2t", "ts", "m2ts", "mts")
	add("video/3gpp", "3gp")
	add("video/3gpp2", "3g2")
	add("video/x-flv", "flv")
	// Audio.
	add("audio/mpeg", "mp3")
	add("audio/mp4", "m4a", "m4b")
	add("audio/aac", "aac")
	add("audio/ogg", "ogg", "oga", "spx")
	add("audio/opus", "opus")
	add("audio/flac", "flac")
	add("audio/wav", "wav")
	add("audio/webm", "weba")
	add("audio/midi", "mid", "midi")
	add("audio/aiff", "aif", "aiff")
	// Documents.
	add("application/pdf", "pdf")
	add("application/rtf", "rtf")
	add("application/msword", "doc")
	add("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx")
	add("application/vnd.ms-excel", "xls")
	add("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx")
	add("application/vnd.ms-powerpoint", "ppt")
	add("application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx")
	add("application/vnd.oasis.opendocument.text", "odt")
	add("application/vnd.oasis.opendocument.spreadsheet", "ods")
	add("application/vnd.oasis.opendocument.presentation", "odp")
	add("application/epub+zip", "epub")
	// Text, data and code (served as text/plain by httpx.ContentType).
	add("text/plain", "txt", "text", "log", "ini", "conf", "cfg", "env", "properties", "gitignore", "diff", "patch", "asc")
	add("text/markdown", "md", "markdown", "mdown", "mkd")
	add("text/csv", "csv")
	add("text/tab-separated-values", "tsv")
	add("text/css", "css", "scss", "sass", "less")
	add("text/calendar", "ics")
	add("text/vcard", "vcf")
	add("text/vtt", "vtt")
	add("text/x-go", "go")
	add("text/x-python", "py", "pyi")
	add("text/x-ruby", "rb")
	add("text/x-rust", "rs")
	add("text/x-java", "java")
	add("text/x-kotlin", "kt", "kts")
	add("text/x-swift", "swift")
	add("text/x-c", "c", "h")
	add("text/x-c++", "cc", "cpp", "cxx", "hh", "hpp", "hxx")
	add("text/x-csharp", "cs")
	add("text/x-lua", "lua")
	add("text/x-perl", "pl", "pm")
	add("text/x-r", "r")
	add("text/x-typescript", "tsx")
	add("text/x-dockerfile", "dockerfile")
	add("text/x-makefile", "mk")
	add("application/json", "json", "map", "webmanifest")
	add("application/x-ndjson", "ndjson", "jsonl")
	add("application/yaml", "yaml", "yml")
	add("application/toml", "toml")
	add("application/sql", "sql")
	add("application/x-sh", "sh", "bash", "zsh", "fish", "ksh")
	add("application/x-php", "php")
	add("application/x-tex", "tex", "sty", "cls")
	add("application/x-subrip", "srt")
	// Markup and scripts (never rendered: always attachments).
	add("text/html", "html", "htm", "shtml")
	add("application/xhtml+xml", "xhtml", "xht")
	add("application/xml", "xml", "xsl", "xslt", "xsd", "rss", "atom", "plist", "gpx", "kml")
	add("text/javascript", "js", "mjs", "cjs", "jsx")
	add("application/wasm", "wasm")
	// Archives and binaries.
	add("application/zip", "zip")
	add("application/gzip", "gz", "tgz")
	add("application/x-tar", "tar")
	add("application/x-bzip2", "bz2", "tbz2")
	add("application/x-xz", "xz", "txz")
	add("application/zstd", "zst", "zstd")
	add("application/x-7z-compressed", "7z")
	add("application/vnd.rar", "rar")
	add("application/x-iso9660-image", "iso")
	add("application/x-apple-diskimage", "dmg")
	add("application/vnd.android.package-archive", "apk")
	add("application/java-archive", "jar")
	add("application/vnd.microsoft.portable-executable", "exe", "dll")
	add("application/x-msi", "msi")
	add("application/vnd.debian.binary-package", "deb")
	add("application/x-rpm", "rpm")
	add("font/woff", "woff")
	add("font/woff2", "woff2")
	add("font/ttf", "ttf")
	add("font/otf", "otf")
}

// MIMEFromName returns the media type implied by name's extension (lowercase,
// without parameters), or "" when the extension is unknown.
func MIMEFromName(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if ext == "" || ext == "." {
		return ""
	}
	if t, ok := builtinMIME[ext]; ok {
		return t
	}
	return BaseMIME(mime.TypeByExtension(ext))
}

// BaseMIME returns the lowercase "type/subtype" of a media type without
// parameters, or "" when v is not a well-formed media type.
func BaseMIME(v string) string {
	if v == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(v)
	if err != nil {
		return ""
	}
	mt = strings.ToLower(mt)
	typ, sub, ok := strings.Cut(mt, "/")
	if !ok || typ == "" || sub == "" || len(mt) > 255 {
		return ""
	}
	return mt
}

// DetectMIME returns the media type to store for a file named name whose
// content starts with head (at most SniffLen bytes are used). hint is an
// optional client-supplied type, used only when the name has no known
// extension. head == nil means the content could not be read: the
// name-derived type is kept. For an empty file pass an empty, non-nil head.
//
// The sniffed type wins when the claimed type is one that browsers render
// inline — images, audio/video and PDF — but the content says otherwise
// (text or markup such as an HTML page named "x.png", or a non-PDF named
// "x.pdf"), so a name can never promote content into an inline type.
// Claimed text, markup and binary types are kept: they are delivered as
// text/plain or as attachments anyway.
func DetectMIME(name, hint string, head []byte) string {
	claimed := MIMEFromName(name)
	if claimed == "" {
		if h := BaseMIME(hint); h != OctetStream {
			claimed = h
		}
	}
	sniff := ""
	if len(head) > 0 {
		if len(head) > SniffLen {
			head = head[:SniffLen]
		}
		sniff = BaseMIME(http.DetectContentType(head))
	}
	switch {
	case claimed == "" && sniff == "":
		if head != nil && len(head) == 0 {
			return "text/plain" // an empty file of unknown type
		}
		return OctetStream
	case claimed == "":
		return sniff
	case sniff == "" || !rendersInline(claimed):
		return claimed
	}
	// claimed is image/*, audio/*, video/* or application/pdf.
	if claimed == "application/pdf" {
		return sniff // must really be a PDF (inline PDFs get a weaker CSP)
	}
	switch {
	case sniff == OctetStream:
		return claimed // opaque binary (AVIF, HEIC, MKV, …): can't disprove the name
	case family(sniff) == family(claimed):
		return claimed // same family: the extension is usually more specific
	case family(sniff) == "":
		return sniff // text, markup, PDF, archives, fonts: the content decides
	}
	return sniff // a different media family (e.g. a JPEG named .mp4)
}

// rendersInline reports whether browsers display t in place (the media part
// of the httpx inline allow-list, plus PDF).
func rendersInline(t string) bool {
	return family(t) != "" || t == "application/pdf"
}

// family groups media types: "image", "av" (audio, video and Ogg) or "".
func family(t string) string {
	typ, _, _ := strings.Cut(t, "/")
	switch {
	case typ == "image" && t != "image/svg+xml":
		return "image"
	case typ == "audio" || typ == "video" || t == "application/ogg":
		return "av"
	}
	return ""
}
