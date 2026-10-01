package ratelimit

import "fileparcel/internal/settings"

// Defaults of the ratelimit.* settings (DESIGN §11.2).
const (
	DefaultLoginPerMin  = 10
	DefaultAPIRPS       = 50
	DefaultAPIBurst     = 200
	DefaultSharePerMin  = 120
	DefaultUnlockPerMin = 5
	// Tailscale Funnel: generous enough for a share gallery (every
	// thumbnail is one request), bounded for the whole internet.
	DefaultFunnelPerMin       = 1200
	DefaultFunnelGlobalPerMin = 12000
)

func init() {
	settings.Register(settings.Def{
		Key: "ratelimit.login_per_min", Section: "ratelimit", Order: 10, Type: settings.TypeInt,
		Default: DefaultLoginPerMin, Min: 1, Max: 10_000,
		Label:       "Sign-in attempts per minute (per IP)",
		Description: "Login, second-factor, passkey, setup and invitation requests allowed per minute from one IP address; starting a passkey sign-in and opening an invitation, which the sign-in pages do on every load, get four times as many. Also the password attempts one IP address may make on a share link.",
	})
	settings.Register(settings.Def{
		Key: "ratelimit.api_rps", Section: "ratelimit", Order: 20, Type: settings.TypeInt,
		Default: DefaultAPIRPS, Min: 1, Max: 100_000,
		Label:       "API requests per second (per IP)",
		Description: "Sustained rate of /api/v1 requests allowed from one IP address.",
	})
	settings.Register(settings.Def{
		Key: "ratelimit.api_burst", Section: "ratelimit", Order: 30, Type: settings.TypeInt,
		Default: DefaultAPIBurst, Min: 1, Max: 1_000_000,
		Label:       "API burst (per IP)",
		Description: "Number of API requests one IP address may send in a quick burst.",
	})
	settings.Register(settings.Def{
		Key: "ratelimit.share_per_min", Section: "ratelimit", Order: 40, Type: settings.TypeInt,
		Default: DefaultSharePerMin, Min: 1, Max: 100_000,
		Label:       "Public share requests per minute (per IP)",
		Description: "Requests to public share links and file requests allowed per minute from one IP address.",
	})
	settings.Register(settings.Def{
		Key: "ratelimit.unlock_per_min", Section: "ratelimit", Order: 50, Type: settings.TypeInt,
		Default: DefaultUnlockPerMin, Min: 1, Max: 1_000,
		Label:       "Unlock attempts per minute (per IP)",
		Description: "Web unlock attempts of a sealed server allowed per minute from one IP address.",
	})
	settings.Register(settings.Def{
		Key: "ratelimit.funnel_per_min", Section: "ratelimit", Order: 60, Type: settings.TypeInt,
		Default: DefaultFunnelPerMin, Min: 1, Max: 100_000,
		Label: "Tailscale Funnel requests per minute (per client)",
		Description: "Requests one internet client may send per minute over Tailscale Funnel (IPv6 clients: per /64 network). " +
			"The other limits apply as well.",
	})
	settings.Register(settings.Def{
		Key: "ratelimit.funnel_global_per_min", Section: "ratelimit", Order: 70, Type: settings.TypeInt,
		Default: DefaultFunnelGlobalPerMin, Min: 1, Max: 1_000_000,
		Label:       "Tailscale Funnel requests per minute (all clients)",
		Description: "Requests all internet clients together may send per minute over Tailscale Funnel.",
	})
}
