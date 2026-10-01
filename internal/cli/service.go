package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"fileparcel/internal/buildinfo"
	"fileparcel/internal/config"
	"fileparcel/internal/home"
	"fileparcel/internal/svc"
)

func init() { Register(newServiceCmd) }

// lcSvcEnv is what every service subcommand needs.
type lcSvcEnv struct {
	h    *home.Home
	host *svc.Host
	rec  *svc.Installed // nil = no install record
}

// lcServiceEnv resolves the home (which must exist) and reads installed.json.
func lcServiceEnv() (*lcSvcEnv, error) {
	h, err := home.Resolve(G.Home)
	if err != nil {
		return nil, err
	}
	if !h.Exists() {
		return nil, notAHomeError(h.Dir())
	}
	rec, err := svc.ReadInstalled(h)
	if err != nil {
		return nil, err
	}
	return &lcSvcEnv{h: h, host: svc.CurrentHost(), rec: rec}, nil
}

// options returns the svc.Options of kind for this home (ports from
// fileparcel.toml, falling back to the install record). Home is spelled as
// the registration names it (svc.RegisteredHome): run through the command
// link, home.Resolve finds the physical path of a home installed under a
// symlinked directory.
func (e *lcSvcEnv) options(kind svc.Kind, boot bool) svc.Options {
	o := svc.Options{Kind: kind, Home: svc.RegisteredHome(e.h, e.rec), Binary: e.h.Binary(), Boot: boot}
	if e.rec != nil {
		o.HTTPSPort, o.HTTPPort = e.rec.HTTPSPort, e.rec.HTTPPort
	}
	if cfg, err := config.Load(e.h); err == nil {
		o.HTTPSPort, o.HTTPPort = cfg.Server.HTTPSPort, cfg.Server.HTTPPort
	}
	if kind.System() {
		// Always the host's service account, never installed.json's
		// service_user: the service account itself can write that file,
		// and root creates the account and chowns the home to it.
		o.User = svc.ServiceUser(e.host)
	}
	return o
}

// recorded returns the recorded kind and boot flag (none when unrecorded).
func (e *lcSvcEnv) recorded() (svc.Kind, bool) {
	if e.rec == nil || e.rec.Kind == "" {
		return svc.KindNone, false
	}
	return e.rec.Kind, e.rec.Boot
}

// manager returns the manager of the registered service: the recorded kind,
// else the platform default kind when a registration for this home exists
// (e.g. the record was lost).
func (e *lcSvcEnv) manager(ctx context.Context) (svc.Manager, error) {
	kind, boot := e.recorded()
	if kind != svc.KindNone {
		return svc.NewManager(e.host, e.options(kind, boot))
	}
	def, why, err := svc.ResolveKind(e.host, "")
	if err != nil {
		return nil, err
	}
	if def == svc.KindNone {
		if why == "" {
			why = "no service is registered"
		}
		return nil, errors.New(why)
	}
	m, err := svc.NewManager(e.host, e.options(def, true))
	if err != nil {
		return nil, err
	}
	if st, err := m.Status(ctx); err != nil || !st.Installed {
		return nil, svc.ErrNotInstalled
	}
	return m, nil
}

// save writes the install record.
func (e *lcSvcEnv) save(rec *svc.Installed) error {
	e.rec = rec
	return svc.WriteInstalled(e.h, rec)
}

// record returns a copy of the install record (a fresh one when missing).
func (e *lcSvcEnv) record() *svc.Installed {
	if e.rec == nil {
		return &svc.Installed{Kind: svc.KindNone, Home: e.h.Dir(), Version: buildinfo.Get().Version,
			InstalledAt: time.Now().UTC()}
	}
	c := *e.rec
	return &c
}

func newServiceCmd() *cobra.Command {
	cmd := groupCmd("service", "Start, stop and register the background service",
		`Run FileParcel as a background service that starts by itself: a systemd user
unit (linked from <HOME>/service; start at boot keeps it running after you log
out), a systemd system unit (/etc/systemd/system, hardened, runs as
"fileparcel"), a launchd agent (~/Library/LaunchAgents) or a launchd daemon
(/Library/LaunchDaemons, runs as "_fileparcel"). What was set up is recorded
in <HOME>/service/installed.json.`,
		`  fileparcel service status
  fileparcel service restart
  fileparcel service install --start`)
	cmd.AddCommand(newServiceInstallCmd(), newServiceUninstallCmd(), newServiceControlCmd("start"),
		newServiceControlCmd("stop"), newServiceControlCmd("restart"), newServiceStatusCmd(),
		newServiceBootCmd(true), newServiceBootCmd(false), newServicePrintCmd())
	return cmd
}

// lcKindFlags resolves --user/--system to a Kind ("" = default).
func lcKindFlags(host *svc.Host, user, system bool) (svc.Kind, error) {
	service := ""
	switch {
	case user && system:
		return "", UsageError("use either --user or --system")
	case user:
		service = "user"
	case system:
		service = "system"
	}
	kind, why, err := svc.ResolveKind(host, service)
	if err != nil {
		return "", err
	}
	if kind == svc.KindNone {
		if why == "" {
			why = "no service manager available"
		}
		return "", errors.New(why)
	}
	return kind, nil
}

func newServiceInstallCmd() *cobra.Command {
	var user, system, boot, noBoot, start, force bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the service (and start it with --start)",
		Long: `Write and register the service for this installation; running it again is
harmless. Start at boot is the default (--no-boot turns it off); for systemd
user services it enables linger, so the server keeps running after you log
out and starts at boot. System services (run as root) create the "fileparcel"
account when needed and give the installation to it (the directory itself,
bin/ and uninstall.sh stay owned by root). --start (re)starts the service and
waits for its health check.`,
		Example: `  fileparcel service install --start
  sudo fileparcel service install --system --start --home /opt/fileparcel
  fileparcel service install --no-boot`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := lcServiceEnv()
			if err != nil {
				return err
			}
			ctx := lcCtx(cmd)
			kind, err := lcKindFlags(e.host, user, system)
			if err != nil {
				return err
			}
			if !user && !system {
				if k, _ := e.recorded(); k != svc.KindNone {
					kind = k
				}
			}
			b := true
			if v := onOff(cmd.Flags(), "boot"); v != nil { // --boot=false = --no-boot
				b = *v
			} else if k, rb := e.recorded(); k == kind {
				b = rb
			}
			o := e.options(kind, b)
			o.Force = force
			rec := e.record()
			if kind.System() {
				created, err := svc.EnsureSystemUser(ctx, e.host, o.User, e.h.Dir())
				if err != nil {
					return err
				}
				if created {
					rec.CreatedUser = o.User
					Infof(cmd, "Created the service account %s", o.User)
				}
				uid, gid, err := svc.AccountIDs(o.User)
				if err != nil {
					return err
				}
				if err := svc.SecureSystemHome(e.h, uid, gid); err != nil {
					return err
				}
			}
			m, err := svc.NewManager(e.host, o)
			if err != nil {
				return err
			}
			if start {
				if err := lcRefuseForeign(ctx, m, e.h); err != nil {
					return fmt.Errorf("%w (or omit --start)", err)
				}
			}
			if kind == svc.KindSystemdUser && b {
				changed, err := svc.EnableLinger(ctx, e.host)
				if err != nil {
					Warnf(cmd, "could not enable linger (%v): the service stops at logout and does not start at boot until you run \"loginctl enable-linger %s\"", err, e.host.User)
				}
				rec.LingerEnabledByUs = rec.LingerEnabledByUs || changed
			}
			if err := m.Install(ctx, start); err != nil {
				return err
			}
			rec.Kind, rec.UnitPath, rec.Boot, rec.Home = kind, m.RegistrationPath(), b, e.h.Dir()
			rec.HTTPSPort, rec.HTTPPort = o.HTTPSPort, o.HTTPPort
			if kind.System() {
				rec.ServiceUser = o.User
			} else {
				rec.ServiceUser = ""
			}
			if err := e.save(rec); err != nil {
				return err
			}
			Successf(cmd, "%s registered (%s; start at boot: %s)", kind.Describe(), m.RegistrationPath(), YesNo(b))
			if start {
				return lcWaitStarted(cmd, e.h, o.HTTPSPort)
			}
			Infof(cmd, "Start it with: fileparcel service start")
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&user, "user", false, "systemd user unit / launchd agent (default for non-root)")
	f.BoolVar(&system, "system", false, "systemd system unit / launchd daemon (root; default for root)")
	f.BoolVar(&boot, "boot", false, "start at boot (default)")
	f.BoolVar(&noBoot, "no-boot", false, "do not start at boot")
	f.BoolVar(&start, "start", false, "start (or restart) the service now")
	f.BoolVar(&force, "force", false, "replace a registration that belongs to another FileParcel home")
	cmd.MarkFlagsMutuallyExclusive("user", "system")
	cmd.MarkFlagsMutuallyExclusive("boot", "no-boot")
	return cmd
}

func newServiceUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and unregister the service (the data stays)",
		Long: `Stop, disable and unregister the service of this installation. Linger is
turned off again when "fileparcel service install" or the installer turned it
on and no other user service needs it. The installation and its data are not
touched (see "fileparcel uninstall").`,
		Example: `  fileparcel service uninstall
  sudo fileparcel service uninstall --home /opt/fileparcel`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := lcServiceEnv()
			if err != nil {
				return err
			}
			ctx := lcCtx(cmd)
			m, err := e.manager(ctx)
			if err != nil {
				return err
			}
			if err := m.Uninstall(ctx); err != nil {
				return err
			}
			rec := e.record()
			if rec.LingerEnabledByUs && m.Kind() == svc.KindSystemdUser {
				if others := svc.OtherUserUnitsEnabled(e.host); len(others) > 0 {
					Infof(cmd, "Linger stays enabled: other user services need it (%v)", others)
				} else if err := svc.DisableLinger(ctx, e.host); err != nil {
					Warnf(cmd, "could not disable linger: %v", err)
				}
				rec.LingerEnabledByUs = false
			}
			rec.Kind, rec.UnitPath, rec.Boot = svc.KindNone, "", false
			if err := e.save(rec); err != nil {
				return err
			}
			Successf(cmd, "%s removed; the data in %s is untouched", m.Kind().Describe(), e.h.Dir())
			return nil
		},
	}
}

// serviceControlTexts are the help texts of "service start", "stop" and
// "restart".
var serviceControlTexts = map[string]struct{ short, long, example string }{
	"start": {"Start the service", `Starts FileParcel through the service manager (systemd or launchd) and waits
until its health check passes (--no-wait returns at once). Does nothing if it
already runs.`, `  fileparcel service start
  fileparcel service start --no-wait`},
	"stop": {"Stop the service", `Stops FileParcel. Web users are disconnected; uploads in progress resume
later. It still starts at the next boot if start at boot is on.`, `  fileparcel service stop
  fileparcel service stop && fileparcel db vacuum && fileparcel service start`},
	"restart": {"Restart the service", `Stops and starts FileParcel and waits for its health check. Use it after
settings that need a restart.`, `  fileparcel service restart
  fileparcel service restart --no-wait`},
}

func newServiceControlCmd(action string) *cobra.Command {
	t := serviceControlTexts[action]
	var wait *waitFlags
	cmd := &cobra.Command{
		Use:     action,
		Short:   t.short,
		Long:    t.long,
		Example: t.example,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := lcServiceEnv()
			if err != nil {
				return err
			}
			ctx := lcCtx(cmd)
			m, err := e.manager(ctx)
			if err != nil {
				return err
			}
			if err := lcControl(ctx, m, e.h, action); err != nil {
				return err
			}
			if action == "stop" {
				Successf(cmd, "stopped")
				return nil
			}
			if !wait.Wait() {
				Successf(cmd, "%sed", action)
				return nil
			}
			return lcWaitStarted(cmd, e.h, 0)
		},
	}
	if action != "stop" {
		wait = addWaitFlags(cmd, true, "the health check passes")
	}
	return cmd
}

// lcWaitStarted waits up to 30 s for the health check of a just started server.
func lcWaitStarted(cmd *cobra.Command, h *home.Home, port int) error {
	Infof(cmd, "Waiting for the server to answer …")
	if err := svc.WaitHealthy(lcCtx(cmd), h, port, 30*time.Second, 500*time.Millisecond); err != nil {
		return fmt.Errorf("%w (see \"fileparcel logs\" and \"fileparcel doctor\")", err)
	}
	Successf(cmd, "the server is running")
	return nil
}

// lcServiceStatus is the JSON of `service status`.
type lcServiceStatus struct {
	*svc.Status
	Boot         bool   `json:"boot"`
	Linger       *bool  `json:"linger,omitempty"`
	RecordedKind string `json:"recorded_kind,omitempty"`
	Home         string `json:"home"`
}

func newServiceStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the service is registered and running",
		Long: `Shows the service manager's view: registered, running, start at boot, unit
file. For the server's own state (addresses, keys, storage) use
"fileparcel status".`,
		Example: `  fileparcel service status
  fileparcel service status --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := lcServiceEnv()
			if err != nil {
				return err
			}
			ctx := lcCtx(cmd)
			m, err := e.manager(ctx)
			if err != nil {
				if errors.Is(err, svc.ErrNotInstalled) || (e.rec == nil || e.rec.Kind == svc.KindNone) {
					out := lcServiceStatus{Status: &svc.Status{Kind: svc.KindNone, State: "not-installed"}, Home: e.h.Dir()}
					return Print(cmd, out, func(w io.Writer) error {
						_, err := fmt.Fprintf(w, "No service is registered for %s (fileparcel service install).\n", e.h.Dir())
						return err
					})
				}
				return err
			}
			st, err := m.Status(ctx)
			if err != nil {
				return err
			}
			out := lcServiceStatus{Status: st, Home: e.h.Dir()}
			if k, b := e.recorded(); k != svc.KindNone {
				out.RecordedKind, out.Boot = string(k), b
			}
			if st.Kind == svc.KindSystemdUser {
				l := svc.LingerEnabled(e.host)
				out.Linger = &l
			}
			return Print(cmd, out, func(w io.Writer) error {
				kv := NewKV()
				kv.Add("Service", st.Kind.Describe())
				kv.Add("Registration", st.Registration)
				kv.Add("Installed", st.Installed)
				kv.Add("Enabled at boot", st.Enabled)
				state := st.State
				if st.SubState != "" {
					state += " (" + st.SubState + ")"
				}
				kv.Add("State", state)
				if st.PID > 0 {
					kv.Add("PID", st.PID)
				}
				if out.Linger != nil {
					kv.Add("Linger", *out.Linger)
				}
				if st.Detail != "" {
					kv.Add("Detail", st.Detail)
				}
				return kv.Render(w)
			})
		},
	}
}

func newServiceBootCmd(enable bool) *cobra.Command {
	use, short := "disable-boot", "Do not start the service at boot"
	long := `Stop FileParcel from starting by itself when the machine boots; a running
server keeps running. For a systemd user service, linger is turned off again
when FileParcel turned it on and no other user service needs it.`
	if enable {
		use, short = "enable-boot", "Start the service at boot"
		long = `Start FileParcel by itself when the machine boots. For a systemd user
service this also turns on linger, so the service runs without anyone being
logged in.`
	}
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Example: fmt.Sprintf(`  fileparcel service %[1]s
  sudo fileparcel service %[1]s --home /opt/fileparcel`, use),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := lcServiceEnv()
			if err != nil {
				return err
			}
			ctx := lcCtx(cmd)
			m, err := e.manager(ctx)
			if err != nil {
				return err
			}
			rec := e.record()
			if enable {
				if err := m.EnableBoot(ctx); err != nil {
					return err
				}
				if m.Kind() == svc.KindSystemdUser {
					changed, err := svc.EnableLinger(ctx, e.host)
					if err != nil {
						Warnf(cmd, "could not enable linger: %v", err)
					}
					rec.LingerEnabledByUs = rec.LingerEnabledByUs || changed
				}
			} else {
				if err := m.DisableBoot(ctx); err != nil {
					return err
				}
				if m.Kind() == svc.KindSystemdUser && rec.LingerEnabledByUs {
					if others := svc.OtherUserUnitsEnabled(e.host); len(others) == 0 {
						if err := svc.DisableLinger(ctx, e.host); err != nil {
							Warnf(cmd, "could not disable linger: %v", err)
						} else {
							rec.LingerEnabledByUs = false
						}
					}
				}
			}
			if rec.Kind == svc.KindNone || rec.Kind == "" {
				rec.Kind, rec.UnitPath = m.Kind(), m.RegistrationPath()
			}
			rec.Boot = enable
			if err := e.save(rec); err != nil {
				return err
			}
			Successf(cmd, "start at boot: %s", YesNo(enable))
			return nil
		},
	}
}

func newServicePrintCmd() *cobra.Command {
	var user, system, noBoot bool
	cmd := &cobra.Command{
		Use:   "print",
		Short: "Show the unit file / plist without installing it",
		Long: `Print the systemd unit or launchd property list that "fileparcel service
install" would register, without changing anything.`,
		Example: `  fileparcel service print
  fileparcel service print --system > fileparcel.service`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := lcServiceEnv()
			if err != nil {
				return err
			}
			kind, err := lcKindFlagsForPrint(e, user, system)
			if err != nil {
				return err
			}
			b, err := svc.Render(e.options(kind, !noBoot))
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
	f := cmd.Flags()
	f.BoolVar(&user, "user", false, "the user unit / launchd agent")
	f.BoolVar(&system, "system", false, "the system unit / launchd daemon")
	f.BoolVar(&noBoot, "no-boot", false, "launchd: RunAtLoad false")
	cmd.MarkFlagsMutuallyExclusive("user", "system")
	return cmd
}

// lcKindFlagsForPrint picks the kind to print; unlike install it does not
// require root for --system (printing changes nothing).
func lcKindFlagsForPrint(e *lcSvcEnv, user, system bool) (svc.Kind, error) {
	goos := e.host.GOOS
	switch {
	case system && goos == "linux":
		return svc.KindSystemdSystem, nil
	case system && goos == "darwin":
		return svc.KindLaunchdDaemon, nil
	case user && goos == "linux":
		return svc.KindSystemdUser, nil
	case user && goos == "darwin":
		return svc.KindLaunchdAgent, nil
	}
	if k, _ := e.recorded(); k != svc.KindNone {
		return k, nil
	}
	return lcKindFlags(e.host, false, false)
}

// lcHomeBusy reports whether another process holds the home lock.
func lcHomeBusy(h *home.Home) bool {
	unlock, err := h.Lock()
	if err != nil {
		return errors.Is(err, home.ErrLocked)
	}
	unlock()
	return false
}

// lcRefuseForeign refuses to start or restart the service of h while a
// FileParcel process outside the service manager holds the home lock (a
// hand-started "fileparcel serve", or an offline command): the unit would
// exit on the lock and restart-loop, and the health check would be answered
// by the foreign server. When the service itself is active it holds the
// lock, so nothing is refused. An unknown service status counts as foreign.
func lcRefuseForeign(ctx context.Context, m svc.Manager, h *home.Home) error {
	if !lcHomeBusy(h) {
		return nil
	}
	st, err := m.Status(ctx)
	if err != nil {
		return fmt.Errorf("another FileParcel process is using this home and the service status is unknown (%v); stop that process first", err)
	}
	if !st.Active {
		return errors.New("a FileParcel process outside the service manager is using this home; stop it first")
	}
	return nil
}

// lcControl runs a service start, stop or restart; start and restart are
// refused while a foreign process uses the home (lcRefuseForeign).
func lcControl(ctx context.Context, m svc.Manager, h *home.Home, action string) error {
	switch action {
	case "start", "restart":
		if err := lcRefuseForeign(ctx, m, h); err != nil {
			return err
		}
		if action == "start" {
			return m.Start(ctx)
		}
		return m.Restart(ctx)
	case "stop":
		return m.Stop(ctx)
	}
	return fmt.Errorf("unknown service action %q", action)
}
