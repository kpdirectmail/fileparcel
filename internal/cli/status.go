package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/buildinfo"
	"fileparcel/internal/config"
	"fileparcel/internal/core"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

func init() { Register(newStatusCmd) }

// lcSystem is the part of GET /api/v1/admin/system that status shows (the
// full object is kept as raw JSON for --json).
type lcSystem struct {
	core.SystemInfo
	Mode      string `json:"mode"`
	BlobCount int64  `json:"blob_count"`
	// StatsUnavailable: a database read of the server failed, so
	// blob_count and blobs_bytes are zeros from that failure, not facts.
	StatsUnavailable bool             `json:"stats_unavailable"`
	Certs            *core.CertStatus `json:"certs,omitempty"`
	MDNS             *core.MDNSStatus `json:"mdns,omitempty"`
	Network          *struct {
		Policy core.AccessPolicy `json:"policy"`
		URLs   []core.AccessURL  `json:"urls"`
	} `json:"network,omitempty"`
	// Maintenance: maintenance mode is on (easy to forget: administrators
	// keep working through it).
	Maintenance bool `json:"maintenance"`
}

// lcStatusReport is the output of `fileparcel status` (--json).
type lcStatusReport struct {
	Home              string          `json:"home,omitempty"`
	Server            string          `json:"server,omitempty"` // remote --server URL
	Running           bool            `json:"running"`
	Transport         string          `json:"transport,omitempty"` // socket | remote
	CLIVersion        string          `json:"cli_version"`
	InstalledVersion  string          `json:"installed_version,omitempty"`
	HTTPSPort         int             `json:"https_port,omitempty"`
	HTTPPort          int             `json:"http_port,omitempty"`
	HomeLocked        bool            `json:"home_locked"` // held by another process
	KeysFile          bool            `json:"keys_file"`
	LastCleanShutdown *time.Time      `json:"last_clean_shutdown,omitempty"`
	RestorePending    bool            `json:"restore_pending,omitempty"`
	RestoreFailed     bool            `json:"restore_failed,omitempty"`
	Service           *svc.Status     `json:"service,omitempty"`
	System            json.RawMessage `json:"system,omitempty"` // GET /admin/system when running
	// Ingress is Tailscale Funnel and Serve (GET /admin/network/tailscale)
	// when running; left out when the server has no such route or refuses it.
	Ingress *core.IngressStatus `json:"ingress,omitempty"`
	Notes   []string            `json:"notes,omitempty"`

	sys *lcSystem
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the server is running and how to reach it",
		Long: `Show the state of FileParcel. When the server is running (on this machine,
or with --server), it reports its version, uptime, keys, certificates, .local
name, addresses, Tailscale Funnel and Serve (when on) and storage. Otherwise
the state of the installation is shown (installed version, ports, service
registration, whether a process holds the installation's lock, pending
restores) without starting anything.`,
		Example: `  fileparcel status
  fileparcel status --json
  fileparcel --home /opt/fileparcel status`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := lcCollectStatus(lcCtx(cmd))
			if err != nil {
				return err
			}
			return Print(cmd, rep, func(w io.Writer) error { return lcRenderStatus(w, rep) })
		},
	}
}

// lcCollectStatus gathers the status report.
func lcCollectStatus(ctx context.Context) (*lcStatusReport, error) {
	rep := &lcStatusReport{CLIVersion: buildinfo.Get().Version}
	if G.Server != "" {
		c, err := Connect(G.ConnectOptions())
		if err != nil {
			return nil, err
		}
		defer c.Close()
		rep.Server, rep.Transport = G.Server, ModeRemote
		if err := lcFetchSystem(ctx, c, rep); err != nil {
			return nil, err
		}
		rep.Running = true
		return rep, nil
	}
	h, err := home.Resolve(G.Home)
	if err != nil {
		return nil, err
	}
	if !h.Exists() {
		return nil, notAHomeError(h.Dir())
	}
	rep.Home = h.Dir()
	rep.InstalledVersion = lcFirstLine(h.VersionFile())
	cfg, err := config.Load(h)
	if err == nil {
		rep.HTTPSPort, rep.HTTPPort = cfg.Server.HTTPSPort, cfg.Server.HTTPPort
	} else {
		rep.Notes = append(rep.Notes, "fileparcel.toml: "+err.Error())
	}
	_, err = os.Stat(h.KeysFile())
	rep.KeysFile = err == nil
	if fi, err := os.Stat(h.CleanShutdownFile()); err == nil {
		t := fi.ModTime().UTC()
		rep.LastCleanShutdown = &t
	}
	_, err = os.Stat(h.RestoreFile())
	rep.RestorePending = err == nil
	_, err = os.Stat(h.RestoreFile() + ".failed")
	rep.RestoreFailed = err == nil
	if st := lcLocalServiceStatus(ctx, h); st != nil {
		rep.Service = st
	}

	c, err := connectSocket(h, Options{})
	switch {
	case err == nil:
		defer c.Close()
		rep.Running, rep.Transport, rep.HomeLocked = true, ModeSocket, true
		if G.Offline {
			// status reports whether the server runs, so it never refuses
			// because it does; say that the flag had no effect.
			rep.Notes = append(rep.Notes, "--offline was ignored: the server answers on the admin socket and the summary comes from it")
		}
		if err := lcFetchSystem(ctx, c, rep); err != nil {
			rep.Notes = append(rep.Notes, "the server answers on the admin socket but GET /admin/system failed: "+err.Error())
		}
	case errors.Is(err, errNoServer):
		rep.HomeLocked = lcHomeBusy(h)
		switch {
		case rep.HomeLocked && cfg != nil && !cfg.AdminSocket.Enabled:
			// Nothing can answer: the lock holder is the server (as in doctor).
			rep.Running = true
			rep.Notes = append(rep.Notes, "the admin socket is disabled in fileparcel.toml (admin_socket.enabled = false): "+
				"this is only the local state of the home; enable it and restart the server for the full status and the other admin commands")
		case rep.HomeLocked:
			rep.Notes = append(rep.Notes, "another process holds the home lock but the admin socket does not answer: an offline admin command is running, or the server hangs (see \"fileparcel doctor\")")
		}
	default:
		rep.Notes = append(rep.Notes, err.Error())
	}
	if !rep.KeysFile {
		rep.Notes = append(rep.Notes, "keys/master.key is missing: the server cannot start")
	}
	if rep.RestoreFailed {
		rep.Notes = append(rep.Notes, "the last scheduled restore failed (see run/restore.json.failed and the log)")
	}
	return rep, nil
}

// lcFetchSystem reads GET /api/v1/admin/system into rep.
func lcFetchSystem(ctx context.Context, c *Client, rep *lcStatusReport) error {
	var raw json.RawMessage
	if err := c.Do(ctx, http.MethodGet, "/api/v1/admin/system", nil, &raw); err != nil {
		return err
	}
	var sys lcSystem
	if err := json.Unmarshal(raw, &sys); err != nil {
		return fmt.Errorf("decode /admin/system: %w", err)
	}
	rep.System, rep.sys = raw, &sys
	// The cached Funnel/Serve state; the report is complete without it.
	if st, err := getIngress(ctx, c, false); err == nil {
		rep.Ingress = st
	}
	return nil
}

// lcLocalServiceStatus returns the registered service's state (nil when none).
func lcLocalServiceStatus(ctx context.Context, h *home.Home) *svc.Status {
	rec, err := svc.ReadInstalled(h)
	if err != nil || rec == nil || rec.Kind == svc.KindNone || rec.Kind == "" {
		return nil
	}
	e := &lcSvcEnv{h: h, host: svc.CurrentHost(), rec: rec}
	m, err := e.manager(ctx)
	if err != nil {
		return &svc.Status{Kind: rec.Kind, State: "unknown", Detail: err.Error()}
	}
	st, err := m.Status(ctx)
	if err != nil {
		return &svc.Status{Kind: rec.Kind, State: "unknown", Detail: err.Error()}
	}
	return st
}

// lcFirstLine returns the first line of a small text file ("" on error).
func lcFirstLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

func lcRenderStatus(w io.Writer, rep *lcStatusReport) error {
	kv := NewKV()
	if rep.sys != nil {
		s := rep.sys
		state := "running"
		if s.PID > 0 {
			state += fmt.Sprintf(" (pid %d", s.PID)
			if s.UptimeSeconds > 0 {
				state += ", up " + HumanDuration(time.Duration(s.UptimeSeconds)*time.Second)
			}
			if s.Supervisor != "" {
				state += ", " + s.Supervisor
			}
			state += ")"
		}
		kv.Add("Server", state)
		ver := s.Version
		if s.Commit != "" {
			ver += " (" + shortCommit(s.Commit) + ")"
		}
		kv.Add("Version", ver)
		if rep.Server != "" {
			kv.Add("Server URL", rep.Server)
		}
		kv.Add("Home", Dash(s.Home))
		keys := string(s.KeysState)
		if s.KeyMode != "" {
			keys += " (" + s.KeyMode + " master key)"
		}
		kv.Add("Keys", keys)
		if s.Maintenance {
			kv.Add("Maintenance", `on: only administrators and roles that operate the server can use it ("fileparcel maintenance off")`)
		}
		if s.Network != nil {
			kv.Add("Access", s.Network.Policy.Mode)
			for i, u := range s.Network.URLs {
				label := ""
				if i == 0 {
					label = "URLs"
				}
				v := u.URL
				if u.Recommended {
					v += "  (recommended)"
				}
				kv.Add(label, v)
			}
		}
		if s.Certs != nil && s.Certs.Leaf != nil {
			kv.Add("Certificate", "valid until "+s.Certs.Leaf.NotAfter.Local().Format("2006-01-02"))
		}
		if s.Certs != nil && s.Certs.CA != nil {
			kv.Add("CA fingerprint", s.Certs.CA.Fingerprint)
		}
		if s.MDNS != nil && s.MDNS.State != "" {
			m := s.MDNS.State
			if s.MDNS.Name != "" {
				m += " " + s.MDNS.Name
			}
			if c := s.MDNS.Configured; c != "" && !strings.EqualFold(c, s.MDNS.Name) {
				m += "  (configured: " + c + ")"
			}
			kv.Add("mDNS", m)
		}
		if in := rep.Ingress; in != nil {
			if l := ingressLine(in.Funnel); l != "off" {
				kv.Add("Funnel", l)
			}
			if l := ingressLine(in.Serve); l != "off" {
				kv.Add("Tailscale Serve", l)
			}
		}
		if s.StatsUnavailable {
			// The database size is a file stat; the blob figures come from
			// queries that failed and are zeros, not an empty store.
			kv.Add("Storage", fmt.Sprintf("database %s; file data unknown (the server could not read its database, see the log)",
				HumanBytes(s.DBBytes)))
		} else {
			kv.Add("Storage", fmt.Sprintf("database %s, %s in %s blobs", HumanBytes(s.DBBytes), HumanBytes(s.BlobsBytes),
				fmt.Sprint(s.BlobCount)))
		}
		if s.DiskSizeBytes > 0 {
			kv.Add("Disk", fmt.Sprintf("%s free of %s", HumanBytes(s.DiskFreeBytes), HumanBytes(s.DiskSizeBytes)))
		}
		if len(s.RestartRequired) > 0 {
			kv.Add("Restart required", strings.Join(s.RestartRequired, ", "))
		}
	} else {
		state := "not running"
		if rep.Running {
			state = "running"
		}
		kv.Add("Server", state)
		kv.Add("Home", rep.Home)
		kv.Add("Installed", Dash(rep.InstalledVersion))
		if rep.HTTPSPort > 0 {
			ports := fmt.Sprintf("HTTPS %d", rep.HTTPSPort)
			if rep.HTTPPort > 0 {
				ports += fmt.Sprintf(", HTTP redirect %d", rep.HTTPPort)
			}
			kv.Add("Ports", ports)
		}
		kv.Add("Master key file", rep.KeysFile)
		if rep.LastCleanShutdown != nil {
			kv.Add("Last clean stop", HumanTime(*rep.LastCleanShutdown))
		}
		if rep.RestorePending {
			kv.Add("Restore", "pending (applied at the next start)")
		}
	}
	kv.Add("CLI version", rep.CLIVersion)
	if rep.Service != nil {
		st := rep.Service.State
		if rep.Service.Enabled {
			st += ", starts at boot"
		}
		kv.Add("Service", rep.Service.Kind.Describe()+": "+st)
	} else if rep.Home != "" {
		kv.Add("Service", "none registered")
	}
	if err := kv.Render(w); err != nil {
		return err
	}
	for _, n := range rep.Notes {
		if _, err := fmt.Fprintln(w, "note: "+n); err != nil {
			return err
		}
	}
	if !rep.Running && rep.Service != nil && rep.Service.Installed {
		_, err := fmt.Fprintln(w, "Start it with: fileparcel service start")
		return err
	}
	return nil
}

// shortCommit returns the first 12 characters of a commit hash (no ellipsis:
// the prefix itself is the identifier users paste into `git show`).
func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}
