package certs

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// parsePlist is a strict XML property-list parser for tests: it accepts the
// Apple DTD subset used by configuration profiles (dict, array, string,
// integer, true, false, data) and rejects anything malformed — keys without
// values, unknown elements, trailing content.
func parsePlist(data []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	var root any
	sawPlist := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if el.Name.Local != "plist" || sawPlist {
				return nil, fmt.Errorf("unexpected <%s>", el.Name.Local)
			}
			sawPlist = true
			if v := attr(el, "version"); v != "1.0" {
				return nil, fmt.Errorf("plist version %q", v)
			}
			v, err := plistValue(dec)
			if err != nil {
				return nil, err
			}
			root = v
			if err := expectEnd(dec, "plist"); err != nil {
				return nil, err
			}
		case xml.CharData:
			if len(bytes.TrimSpace(el)) > 0 {
				return nil, errors.New("text outside <plist>")
			}
		case xml.Directive:
			if !strings.HasPrefix(string(el), "DOCTYPE plist") {
				return nil, fmt.Errorf("unexpected directive %q", el)
			}
		}
	}
	if !sawPlist {
		return nil, errors.New("no <plist>")
	}
	return root, nil
}

func attr(el xml.StartElement, name string) string {
	for _, a := range el.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// nextStart returns the next start element, skipping whitespace; an end
// element yields (nil, name).
func nextStart(dec *xml.Decoder) (*xml.StartElement, string, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, "", err
		}
		switch el := tok.(type) {
		case xml.StartElement:
			return &el, "", nil
		case xml.EndElement:
			return nil, el.Name.Local, nil
		case xml.CharData:
			if len(bytes.TrimSpace(el)) > 0 {
				return nil, "", fmt.Errorf("unexpected text %q", el)
			}
		case xml.Comment:
		default:
			return nil, "", fmt.Errorf("unexpected token %T", tok)
		}
	}
}

func expectEnd(dec *xml.Decoder, name string) error {
	el, end, err := nextStart(dec)
	if err != nil {
		return err
	}
	if el != nil || end != name {
		return fmt.Errorf("expected </%s>", name)
	}
	return nil
}

func text(dec *xml.Decoder, name string) (string, error) {
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch el := tok.(type) {
		case xml.CharData:
			b.Write(el)
		case xml.EndElement:
			if el.Name.Local != name {
				return "", fmt.Errorf("mismatched </%s>", el.Name.Local)
			}
			return b.String(), nil
		default:
			return "", fmt.Errorf("unexpected %T in <%s>", tok, name)
		}
	}
}

// plistValue reads exactly one value element.
func plistValue(dec *xml.Decoder) (any, error) {
	el, end, err := nextStart(dec)
	if err != nil {
		return nil, err
	}
	if el == nil {
		return nil, fmt.Errorf("expected a value, got </%s>", end)
	}
	return valueOf(dec, *el)
}

func valueOf(dec *xml.Decoder, el xml.StartElement) (any, error) {
	switch el.Name.Local {
	case "dict":
		m := map[string]any{}
		for {
			k, end, err := nextStart(dec)
			if err != nil {
				return nil, err
			}
			if k == nil {
				if end != "dict" {
					return nil, fmt.Errorf("mismatched </%s>", end)
				}
				return m, nil
			}
			if k.Name.Local != "key" {
				return nil, fmt.Errorf("expected <key>, got <%s>", k.Name.Local)
			}
			key, err := text(dec, "key")
			if err != nil {
				return nil, err
			}
			if _, dup := m[key]; dup {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			v, err := plistValue(dec)
			if err != nil {
				return nil, fmt.Errorf("key %q: %w", key, err)
			}
			m[key] = v
		}
	case "array":
		var a []any
		for {
			v, end, err := nextStart(dec)
			if err != nil {
				return nil, err
			}
			if v == nil {
				if end != "array" {
					return nil, fmt.Errorf("mismatched </%s>", end)
				}
				return a, nil
			}
			x, err := valueOf(dec, *v)
			if err != nil {
				return nil, err
			}
			a = append(a, x)
		}
	case "string":
		return text(dec, "string")
	case "integer":
		s, err := text(dec, "integer")
		if err != nil {
			return nil, err
		}
		return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	case "true", "false":
		if err := expectEnd(dec, el.Name.Local); err != nil {
			return nil, err
		}
		return el.Name.Local == "true", nil
	case "data":
		s, err := text(dec, "data")
		if err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	}
	return nil, fmt.Errorf("unsupported element <%s>", el.Name.Local)
}
