package mdns

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Backend kinds (MDNSStatus.Backend; mdns.mode also accepts "auto" and "off").
const (
	BackendAvahi   = "avahi"
	BackendDNSSD   = "dnssd"
	BackendBuiltin = "builtin"
	BackendNone    = "none"
)

// Modes of mdns.mode.
const (
	ModeAuto = "auto"
	ModeOff  = "off"
)

// ServiceType is the DNS-SD service type published (DESIGN §10.5).
const ServiceType = "_https._tcp"

// errCollision reports that the host name <name>.local is already taken on
// the network; the supervisor retries with "<name>-2", "-3", ….
var errCollision = errors.New("mdns: name collision")

// errInstanceCollision reports that the DNS-SD service instance name is
// taken while the host label is free — typically another FileParcel on this
// machine, since the instance is "FileParcel on <computer name>". Only the
// instance is renamed ("… (2)", "… (3)", …); <name>.local must survive,
// because it is what the leaf certificate, the URLs and the WebAuthn RP ID
// are built from.
var errInstanceCollision = errors.New("mdns: service instance collision")

// stateInstanceCollision is the backendEvent state for an asynchronously
// reported errInstanceCollision. It is internal to the backend/supervisor
// protocol and is never stored in a core.MDNSStatus.
const stateInstanceCollision = "instance-collision"

// ifaceAddrs are the addresses published on one interface.
type ifaceAddrs struct {
	Name  string
	Index int
	Addrs []netip.Addr
}

// publication is what a backend publishes: the host record(s)
// <Host>.local → Addrs and the _https._tcp service instance.
type publication struct {
	Host     string // DNS label without ".local", e.g. "fileparcel" or "fileparcel-2"
	Instance string // DNS-SD instance name, e.g. "FileParcel on nas"
	Port     int
	TXT      []string // "path=/", "fp=1"
	Ifaces   []ifaceAddrs
	// Loopback admits loopback interfaces (tests only).
	Loopback bool
}

// FQDN returns "<Host>.local".
func (p publication) FQDN() string { return p.Host + ".local" }

// equal reports whether two publications are identical.
func (p publication) equal(o publication) bool {
	if p.Host != o.Host || p.Instance != o.Instance || p.Port != o.Port || p.Loopback != o.Loopback ||
		!slices.Equal(p.TXT, o.TXT) || len(p.Ifaces) != len(o.Ifaces) {
		return false
	}
	for i := range p.Ifaces {
		a, b := p.Ifaces[i], o.Ifaces[i]
		if a.Name != b.Name || a.Index != b.Index || !slices.Equal(a.Addrs, b.Addrs) {
			return false
		}
	}
	return true
}

// ifaceNames lists the interface names of p.
func (p publication) ifaceNames() []string {
	out := make([]string, 0, len(p.Ifaces))
	for _, i := range p.Ifaces {
		out = append(out, i.Name)
	}
	return out
}

// allAddrs returns every address of p, IPv4 first.
func (p publication) allAddrs() []netip.Addr {
	var v4, v6 []netip.Addr
	for _, i := range p.Ifaces {
		for _, a := range i.Addrs {
			if a.Is4() {
				v4 = append(v4, a)
			} else {
				v6 = append(v6, a)
			}
		}
	}
	return append(v4, v6...)
}

// backendEvent is an asynchronous state report of a backend for the
// publication generation gen.
type backendEvent struct {
	gen   uint64
	state string // core.MDNSPublishing | MDNSPublished | MDNSCollision | MDNSError
	err   error
}

// backend publishes one publication at a time.
type backend interface {
	// kind returns the Backend* constant.
	kind() string
	// publish replaces the current publication with p (generation gen).
	// It returns errCollision (host name taken) or errInstanceCollision
	// (only the DNS-SD instance name taken) for collisions detected
	// synchronously; later state changes are reported through the emit func
	// given at creation.
	publish(ctx context.Context, gen uint64, p publication) error
	// unpublish withdraws the current publication (best effort, idempotent).
	unpublish()
	// close unpublishes and releases every resource (idempotent).
	close() error
}

// hostLabel returns the host label of attempt n (1 = base, then base-2, …),
// truncating base so the label stays within 63 bytes.
func hostLabel(base string, n int) string {
	if n <= 1 {
		return base
	}
	suffix := "-" + strconv.Itoa(n)
	if len(base)+len(suffix) > 63 {
		base = strings.TrimRight(base[:63-len(suffix)], "-")
	}
	return base + suffix
}

// instanceName returns the DNS-SD instance name of attempt n
// ("FileParcel on nas", then "FileParcel on nas (2)", …) within 63 bytes.
func instanceName(base string, n int) string {
	suffix := ""
	if n > 1 {
		suffix = " (" + strconv.Itoa(n) + ")"
	}
	return truncateUTF8(base, 63-len(suffix)) + suffix
}

// instanceRenamed reports whether s already carries an instanceName suffix
// (" (2)", " (3)", …), i.e. whether the instance has been renamed at least
// once to get out of the way of another publisher.
func instanceRenamed(s string) bool {
	if !strings.HasSuffix(s, ")") {
		return false
	}
	i := strings.LastIndex(s, " (")
	if i < 0 {
		return false
	}
	n, err := strconv.Atoi(s[i+2 : len(s)-1])
	return err == nil && n > 1
}

// truncateUTF8 cuts s to at most n bytes on a rune boundary.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// validLabel reports whether s is a DNS label (a-z, 0-9, '-', 1..63 bytes,
// not starting or ending with '-').
func validLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
