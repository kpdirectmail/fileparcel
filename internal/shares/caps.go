package shares

import "fileparcel/internal/core"

// shareCapRefusal says why p's role may not create shares of kind ("" =
// it may): links need shares.links, file requests shares.requests (DESIGN
// §6a). The principal's capabilities are resolved on every request, so a
// role change applies to the next call.
func shareCapRefusal(p *core.Principal, kind string) string {
	if kind == core.ShareRequest {
		if !p.Can(core.CapShareRequests) {
			return "your role does not allow file requests"
		}
		return ""
	}
	if !p.Can(core.CapShareLinks) {
		return "your role does not allow share links"
	}
	return ""
}
