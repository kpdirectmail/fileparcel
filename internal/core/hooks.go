package core

// Optional lifecycle hooks. wire.Build checks every constructed service for
// these interfaces (type assertion), so a unit can use them without editing
// the frozen wire package:
//
//  1. all constructors run in the fixed order of DESIGN §5.2;
//  2. Bind(*Services) is called on every service implementing Binder;
//  3. RegisterJobs(Jobs) is called on every service implementing JobRegistrar;
//  4. wire.Start calls Start (net → certs → mdns → jobs);
//  5. the cleanup func returned by wire.Build calls Close() on every service
//     implementing io.Closer, in reverse construction order, then closes the
//     bus, the database and the log file.

// Services is the set of constructed services, for late binding.
type Services struct {
	Keys     Keys
	Settings Settings
	Audit    Audit
	Jobs     Jobs
	Blobs    BlobStore
	Users    Users
	Auth     Auth
	Files    Files
	Uploads  Uploads
	Shares   Shares
	Network  Network
	Certs    Certs
	MDNS     MDNS
	Backups  Backups
	Notify   Notify
	Ingress  Ingress // Tailscale Funnel/Serve; nil until package tsingress is wired
}

// Binder lets a service pick up optional collaborators that its fixed
// constructor signature does not provide (e.g. shares → Notify for
// notify_owner). Required dependencies belong in New. Bind must not call
// other services (they may not be bound yet); just store references.
type Binder interface {
	Bind(s *Services) error
}

// JobRegistrar lets a service contribute job kinds and schedules (DESIGN §9.7)
// even if its constructor does not receive Jobs (keys, auth, audit, certs,
// blobstore, …). Called after Bind, before Start.
type JobRegistrar interface {
	RegisterJobs(j Jobs) error
}
