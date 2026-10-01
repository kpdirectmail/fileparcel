package certs

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"

	"fileparcel/internal/core"
)

// CA export formats and their media types.
const (
	FormatPEM          = "pem"
	FormatDER          = "der"
	FormatCRT          = "crt" // alias of der
	FormatMobileconfig = "mobileconfig"

	MIMEPEM          = "application/x-pem-file"
	MIMEDER          = "application/x-x509-ca-cert"
	MIMEMobileconfig = "application/x-apple-aspen-config"
)

// CAExport implements core.Certs: the local CA certificate as PEM, DER
// ("der" or "crt") or an Apple configuration profile ("mobileconfig",
// com.apple.security.root payload) for iOS/macOS.
func (svc *Service) CAExport(format string) (data []byte, contentType, filename string, err error) {
	ca := svc.snapshot().ca
	if ca == nil {
		return nil, "", "", core.NotFoundf(`the local CA does not exist yet; run "fileparcel init"`)
	}
	base := "fileparcel-ca"
	if c := svc.env.Config; c != nil && c.Server.Name != "" && validDNSName(c.Server.Name, false) {
		base = c.Server.Name + "-ca"
	}
	switch strings.ToLower(format) {
	case FormatPEM, "":
		return certPEM(ca.Raw), MIMEPEM, base + ".pem", nil
	case FormatDER, FormatCRT:
		return bytes.Clone(ca.Raw), MIMEDER, base + ".crt", nil
	case FormatMobileconfig:
		return svc.mobileconfig(ca.Raw, ca.Subject.CommonName), MIMEMobileconfig, base + ".mobileconfig", nil
	}
	return nil, "", "", core.Invalid("format", "format must be pem, der or mobileconfig")
}

// payloadUUID derives a stable UUID (RFC 4122 v5 layout) from the CA
// certificate so that re-downloading the profile updates the same profile.
func payloadUUID(der []byte, purpose string) string {
	h := sha256.New()
	h.Write([]byte("fileparcel-mobileconfig|" + purpose + "|"))
	h.Write(der)
	s := h.Sum(nil)[:16]
	s[6] = (s[6] & 0x0f) | 0x50
	s[8] = (s[8] & 0x3f) | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16]))
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// mobileconfig renders an unsigned configuration profile with one root
// certificate payload.
func (svc *Service) mobileconfig(der []byte, caName string) []byte {
	instance, id := "fileparcel", "local"
	if c := svc.env.Config; c != nil {
		if c.Server.Name != "" {
			instance = c.Server.Name
		}
		if c.InstallID != "" {
			id = c.InstallID
		}
	}
	ident := "com.fileparcel.ca." + strings.ToLower(id)
	b64 := base64.StdEncoding.EncodeToString(der)
	var wrapped strings.Builder
	for i := 0; i < len(b64); i += 64 {
		wrapped.WriteString("\t\t\t")
		wrapped.WriteString(b64[i:min(i+64, len(b64))])
		wrapped.WriteString("\n")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>%[1]s</string>
			<key>PayloadContent</key>
			<data>
%[2]s			</data>
			<key>PayloadDescription</key>
			<string>Adds the FileParcel local certificate authority as a trusted root.</string>
			<key>PayloadDisplayName</key>
			<string>%[3]s</string>
			<key>PayloadIdentifier</key>
			<string>%[4]s.root</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%[5]s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Trust the HTTPS certificate of the FileParcel server %[6]s. Verify the fingerprint shown on the server's /trust page: %[7]s</string>
	<key>PayloadDisplayName</key>
	<string>FileParcel CA (%[6]s)</string>
	<key>PayloadIdentifier</key>
	<string>%[4]s</string>
	<key>PayloadOrganization</key>
	<string>FileParcel</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%[8]s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, xmlEscape(instance+"-ca.cer"), wrapped.String(), xmlEscape(caName), xmlEscape(ident),
		payloadUUID(der, "root"), xmlEscape(instance), fingerprint(der), payloadUUID(der, "profile"))
	return b.Bytes()
}
