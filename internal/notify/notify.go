// Package notify sends optional e-mail notifications over SMTP using text
// templates (DESIGN §2, §11.2 "email"). Owned by unit C.
//
// E-mail is enabled when the setting smtp.host is non-empty. Transport
// security follows smtp.tls: "starttls" (the default; the server must offer
// STARTTLS, otherwise sending fails instead of silently falling back to
// clear text), "tls" (implicit TLS) or "none". Authentication is AUTH PLAIN
// and is only ever attempted over TLS. Server certificates are verified
// against the system roots with the configured host name.
//
// Send never blocks the caller on the network: it validates the request,
// renders the template and queues one message per recipient; a background
// worker delivers them with a per-attempt timeout and a small number of
// retries for transient failures. Test sends synchronously so the
// administrator sees the SMTP error. Categories that are not listed in
// notify.events are skipped silently (Send returns nil).
//
// The available templates and their data keys are documented on the
// Template* constants.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"fileparcel/internal/core"
	"fileparcel/internal/crypt"
)

// Tunables.
const (
	// QueueSize bounds the number of queued messages.
	QueueSize = 256
	// MaxRecipients bounds the recipients of one Send call.
	MaxRecipients = 50
	// dialTimeout bounds the TCP (and TLS) connection setup.
	dialTimeout = 15 * time.Second
	// attemptTimeout bounds one delivery attempt.
	attemptTimeout = 60 * time.Second
	// testTimeout bounds Test.
	testTimeout = 30 * time.Second
	// drainTimeout bounds the delivery of queued messages at Close.
	drainTimeout = 10 * time.Second
	// defaultInstance is used when ui.instance_name is empty.
	defaultInstance = "FileParcel"
	// instanceSetting is the instance name setting (registered by the pages unit).
	instanceSetting = "ui.instance_name"
)

// retryDelays are the waits before the 2nd and 3rd delivery attempt.
var retryDelays = []time.Duration{5 * time.Second, 30 * time.Second}

// Service implements core.Notify.
type Service struct {
	env *core.Env
	log *slog.Logger

	queue     chan *message
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	// Test hooks (nil in production): extra trusted roots for the SMTP
	// server certificate and a replacement for the retry delays.
	rootCAs *x509.CertPool
	delays  []time.Duration
}

var _ core.Notify = (*Service)(nil)

// message is one queued e-mail to a single recipient.
type message struct {
	tmpl    string
	to      string
	subject string
	body    string
}

// New creates the service and starts its delivery worker (constructor
// signature fixed by DESIGN §5.2). Close stops the worker.
func New(env *core.Env) (*Service, error) {
	if env == nil {
		return nil, errors.New("notify: env required")
	}
	log := env.Log
	if log == nil {
		log = slog.Default()
	}
	s := &Service{
		env:   env,
		log:   log.With("component", "notify"),
		queue: make(chan *message, QueueSize),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go s.worker()
	return s, nil
}

// Close stops the delivery worker after trying to deliver the queued messages
// for a few seconds (io.Closer, called by the wire cleanup). Idempotent.
func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		select {
		case <-s.done:
		case <-time.After(drainTimeout + 5*time.Second):
			s.log.Warn("notify: delivery worker did not stop in time")
		}
	})
	return nil
}

// Enabled reports whether e-mail is configured (smtp.host is set).
func (s *Service) Enabled() bool {
	return s.env.Settings != nil && strings.TrimSpace(s.env.Settings.String(SettingHost)) != ""
}

// Send renders tmpl with data and queues one e-mail per recipient. It returns
// an error when e-mail is disabled (503 unavailable), for invalid recipients or
// data (422), and when the queue is full (503); delivery failures are only
// logged. Notifications whose category is not enabled in notify.events are
// skipped and Send returns nil.
func (s *Service) Send(ctx context.Context, to []string, tmpl string, data any) error {
	if !s.Enabled() {
		return core.Errorf(core.ErrUnavailable, "e-mail notifications are not configured")
	}
	rcpts, err := cleanRecipients(to)
	if err != nil {
		return err
	}
	r, err := render(tmpl, data, s.common())
	if err != nil {
		return err
	}
	if r.category != "" && !slices.Contains(s.env.Settings.Strings(SettingEvents), r.category) {
		return nil
	}
	select {
	case <-s.stop:
		return core.Errorf(core.ErrUnavailable, "the mail service is shutting down")
	default:
	}
	queued := 0
	for _, rc := range rcpts {
		m := &message{tmpl: tmpl, to: rc, subject: r.subject, body: r.body}
		select {
		case s.queue <- m:
			queued++
		default:
			s.log.Error("notify: mail queue full; message dropped", "template", tmpl, "dropped", len(rcpts)-queued)
			return core.Errorf(core.ErrUnavailable, "the mail queue is full; try again later")
		}
	}
	return nil
}

// Test sends the test template to one address synchronously and returns the
// delivery error (422 for a bad address, 503 with the SMTP error otherwise).
func (s *Service) Test(ctx context.Context, to string) error {
	if !s.Enabled() {
		return core.Errorf(core.ErrUnavailable, "e-mail notifications are not configured (set smtp.host)")
	}
	rcpts, err := cleanRecipients([]string{to})
	if err != nil {
		return err
	}
	r, err := render(TemplateTest, nil, s.common())
	if err != nil {
		return err
	}
	cfg, err := s.config()
	if err != nil {
		return err
	}
	tctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()
	if err := s.deliver(tctx, cfg, &message{tmpl: TemplateTest, to: rcpts[0], subject: r.subject, body: r.body}); err != nil {
		return core.Wrap(core.ErrUnavailable, "sending the test e-mail failed: "+safeErr(err), err)
	}
	return nil
}

// common returns the fields every template receives.
func (s *Service) common() map[string]string {
	inst := ""
	if s.env.Settings != nil {
		inst = strings.TrimSpace(s.env.Settings.String(instanceSetting))
	}
	if inst == "" {
		inst = defaultInstance
	}
	return map[string]string{"instance": cleanSubject(inst), "time": s.env.Now().UTC().Format(time.RFC3339)}
}

// cleanRecipients validates and deduplicates bare e-mail addresses.
func cleanRecipients(to []string) ([]string, error) {
	if len(to) == 0 {
		return nil, core.Invalid("to", "at least one recipient is required")
	}
	if len(to) > MaxRecipients {
		return nil, core.Invalid("to", fmt.Sprintf("at most %d recipients", MaxRecipients))
	}
	out := make([]string, 0, len(to))
	for _, t := range to {
		t = strings.TrimSpace(t)
		a, err := mail.ParseAddress(t)
		if err != nil || a.Address != t || len(t) > 254 || strings.ContainsAny(t, "\r\n<>") {
			return nil, core.Invalid("to", fmt.Sprintf("%q is not a valid e-mail address", truncate(t, 100)))
		}
		if !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, t) }) {
			out = append(out, t)
		}
	}
	return out, nil
}

// ---------- configuration ----------

// smtpConfig is a snapshot of the SMTP settings.
type smtpConfig struct {
	host     string
	port     int
	mode     string
	username string
	password string
	from     *mail.Address
}

// config reads the current SMTP settings.
func (s *Service) config() (*smtpConfig, error) {
	st := s.env.Settings
	if st == nil {
		return nil, core.Errorf(core.ErrUnavailable, "settings unavailable")
	}
	c := &smtpConfig{
		host:     strings.TrimSpace(st.String(SettingHost)),
		port:     int(st.Int(SettingPort)),
		mode:     st.String(SettingTLS),
		username: st.String(SettingUsername),
	}
	if c.host == "" {
		return nil, core.Errorf(core.ErrUnavailable, "e-mail notifications are not configured (set smtp.host)")
	}
	if c.port <= 0 || c.port > 65535 {
		c.port = 587
	}
	switch c.mode {
	case TLSStartTLS, TLSImplicit, TLSNone:
	default:
		c.mode = TLSStartTLS
	}
	if c.username != "" {
		if c.mode == TLSNone {
			return nil, core.Invalid(SettingTLS, "SMTP authentication needs an encrypted connection: set smtp.tls to starttls or tls")
		}
		pw, err := st.Secret(SettingPassword)
		if err != nil {
			return nil, core.Wrap(core.ErrUnavailable, "the SMTP password cannot be read", err)
		}
		c.password = pw
	}
	from, err := s.fromAddress(c)
	if err != nil {
		return nil, err
	}
	c.from = from
	return c, nil
}

// fromAddress resolves the sender: smtp.from, else smtp.username when it is an
// address. A missing display name becomes the instance name.
func (s *Service) fromAddress(c *smtpConfig) (*mail.Address, error) {
	raw := strings.TrimSpace(s.env.Settings.String(SettingFrom))
	if raw == "" && strings.Contains(c.username, "@") {
		raw = c.username
	}
	if raw == "" {
		return nil, core.Invalid(SettingFrom, "set a sender address (smtp.from)")
	}
	a, err := mail.ParseAddress(raw)
	if err != nil || strings.ContainsAny(a.Address, "\r\n<>") {
		return nil, core.Invalid(SettingFrom, "the sender address (smtp.from) is not valid")
	}
	if a.Name == "" {
		a.Name = s.common()["instance"]
	}
	return a, nil
}

// ---------- delivery ----------

// worker delivers queued messages until Close.
func (s *Service) worker() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			s.drain()
			return
		case m := <-s.queue:
			s.deliverWithRetry(m)
		}
	}
}

// drain makes one quick attempt at every queued message.
func (s *Service) drain() {
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	lost := 0
	for {
		select {
		case m := <-s.queue:
			if ctx.Err() != nil {
				lost++
				continue
			}
			cfg, err := s.config()
			if err == nil {
				err = s.deliver(ctx, cfg, m)
			}
			if err != nil {
				lost++
				s.log.Warn("notify: delivery failed during shutdown", "template", m.tmpl, "err", safeErr(err))
			}
		default:
			if lost > 0 {
				s.log.Error("notify: messages not delivered before shutdown", "count", lost)
			}
			return
		}
	}
}

// deliverWithRetry delivers m, retrying transient failures.
func (s *Service) deliverWithRetry(m *message) {
	delays := retryDelays
	if s.delays != nil {
		delays = s.delays
	}
	var err error
	for attempt := 0; ; attempt++ {
		var cfg *smtpConfig
		if cfg, err = s.config(); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
			go func() { // Close aborts the attempt (the message is re-queued below)
				select {
				case <-s.stop:
					cancel()
				case <-ctx.Done():
				}
			}()
			err = s.deliver(ctx, cfg, m)
			cancel()
			if err == nil {
				s.log.Debug("notify: e-mail sent", "template", m.tmpl, "domain", domainOf(m.to))
				return
			}
		}
		if attempt >= len(delays) || permanent(err) {
			break
		}
		select {
		case <-s.stop:
			// Close is draining; hand the message back if there is room.
			select {
			case s.queue <- m:
			default:
			}
			return
		case <-time.After(delays[attempt]):
		}
	}
	s.log.Warn("notify: e-mail not delivered", "template", m.tmpl, "domain", domainOf(m.to), "err", safeErr(err))
}

// permanent reports whether err is a permanent failure (configuration error or
// SMTP 5xx reply) that a retry would not fix.
func permanent(err error) bool {
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code >= 500
	}
	var ce *core.Error
	if errors.As(err, &ce) {
		return ce.Code == core.ErrInvalid.Code
	}
	var ue x509.UnknownAuthorityError
	var he x509.HostnameError
	return errors.As(err, &ue) || errors.As(err, &he)
}

// deliver sends one message over a fresh SMTP connection.
func (s *Service) deliver(ctx context.Context, cfg *smtpConfig, m *message) error {
	addr := net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port))
	tlsCfg := &tls.Config{ServerName: cfg.host, MinVersion: tls.VersionTLS12, RootCAs: s.rootCAs}
	nd := &net.Dialer{Timeout: dialTimeout}
	var conn net.Conn
	var err error
	if cfg.mode == TLSImplicit {
		conn, err = (&tls.Dialer{NetDialer: nd, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = nd.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	// Abort the whole conversation when ctx ends.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, cfg.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer c.Close()
	if err := c.Hello(helloName()); err != nil {
		return fmt.Errorf("smtp EHLO: %w", err)
	}
	if cfg.mode == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return core.Invalid(SettingTLS, "the SMTP server does not offer STARTTLS; use smtp.tls = tls or none")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp STARTTLS: %w", err)
		}
	}
	if cfg.username != "" {
		if _, isTLS := c.TLSConnectionState(); !isTLS {
			return core.Invalid(SettingTLS, "SMTP authentication needs an encrypted connection")
		}
		ok, mechs := c.Extension("AUTH")
		if !ok || !slices.Contains(strings.Fields(strings.ToUpper(mechs)), "PLAIN") {
			return core.Invalid(SettingUsername, "the SMTP server does not offer AUTH PLAIN")
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.username, cfg.password, cfg.host)); err != nil {
			return fmt.Errorf("smtp authentication: %w", err)
		}
	}
	if err := c.Mail(cfg.from.Address); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(m.to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(buildMessage(cfg.from, m, s.env.Now())); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if err := c.Quit(); err != nil {
		// The message was accepted (DATA succeeded); a failed QUIT is harmless.
		s.log.Debug("notify: smtp QUIT failed", "err", err)
	}
	return nil
}

// buildMessage renders the RFC 5322 message (text/plain, UTF-8, quoted-printable).
func buildMessage(from *mail.Address, m *message, now time.Time) []byte {
	var b bytes.Buffer
	hdr := func(k, v string) {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}
	hdr("From", from.String())
	hdr("To", (&mail.Address{Address: m.to}).String())
	hdr("Subject", mime.QEncoding.Encode("utf-8", m.subject))
	hdr("Date", now.Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(crypt.RandomBytes(16))+"@"+domainOf(from.Address)+">")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", `text/plain; charset="utf-8"`)
	hdr("Content-Transfer-Encoding", "quoted-printable")
	hdr("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(m.body))
	_ = qp.Close()
	return b.Bytes()
}

// helloName is the EHLO name: the host name when it looks like a DNS name.
func helloName() string {
	h, err := os.Hostname()
	if err != nil || h == "" || strings.ContainsFunc(h, func(r rune) bool {
		return !(r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) {
		return "localhost"
	}
	return h
}

// domainOf returns the domain part of an address ("localhost" when missing).
func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 && i < len(addr)-1 {
		return addr[i+1:]
	}
	return "localhost"
}

// safeErr renders err for logs and API messages (bounded, single line).
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	return cleanSubject(err.Error())
}
