package opsapi

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"fileparcel/internal/app"
	"fileparcel/internal/core"
	"fileparcel/internal/events"
)

// The stream principals of the tests below: holders of custom roles with the
// listed permissions (plus Member's), by session or by API token.
func init() {
	principals["networker"] = delegate("nora", core.CapNetworkManage)
	tok := delegate("nora", core.CapNetworkManage)
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeFilesRead}
	principals["networker files token"] = tok
	tok = delegate("nora", core.CapNetworkManage)
	tok.Via, tok.Scopes = core.ViaToken, []string{core.ScopeAdmin}
	principals["networker admin token"] = tok
	principals["certifier"] = delegate("cid", core.CapCertsManage)
	principals["settings"] = delegate("sam", core.CapSettingsManage)
	principals["helpdesk"] = delegate("hd", core.CapUsersView)
	holder := delegate("rho", core.CapShareLinks)
	holder.RoleID = "rol_01k5z8r3m9d4q7w2x6c1v0b5r1"
	principals["holder"] = holder
}

// The delivery rule of every topic per permission (DESIGN §6a, topicCaps).
func TestSSEDeliverable(t *testing.T) {
	job := func(user string) events.Event {
		return events.Event{Topic: events.TopicJobDone, UserID: user, Data: core.JobEvent{Job: &core.Job{ID: "job_1"}}}
	}
	authz := func(ev core.AuthzChangedEvent) events.Event {
		return events.Event{Topic: events.TopicAuthzChanged, Data: ev}
	}
	cases := map[string]events.Event{
		"own job":       job("usr_otto"),
		"other job":     job("usr_bob"),
		"settings":      {Topic: events.TopicSettingsChanged, Data: core.SettingsChangedEvent{Keys: []string{"x"}}},
		"network":       {Topic: events.TopicNetworkChanged},
		"mdns":          {Topic: events.TopicMDNSChanged},
		"ingress":       {Topic: events.TopicIngressChanged},
		"certs":         {Topic: events.TopicCertsChanged},
		"backup":        {Topic: events.TopicBackupFinished},
		"restart":       {Topic: events.TopicSystemRestart},
		"keys":          {Topic: events.TopicKeysState},
		"custom":        {Topic: "custom.secret"},
		"authz user":    authz(core.AuthzChangedEvent{UserIDs: []string{"usr_otto"}, Reason: core.AuthzRoleAssigned}),
		"authz role":    authz(core.AuthzChangedEvent{RoleID: "rol_01k5z8r3m9d4q7w2x6c1v0b5na", Reason: core.AuthzRoleUpdated}),
		"authz other":   authz(core.AuthzChangedEvent{UserIDs: []string{"usr_zed"}, Reason: core.AuthzRoleAssigned}),
		"authz no data": {Topic: events.TopicAuthzChanged},
	}
	all := []string{"own job", "other job", "settings", "network", "mdns", "ingress", "certs", "backup", "keys",
		"authz user", "authz role", "authz other"}
	for who, want := range map[string][]string{
		"alice":    {"keys"},
		"admin":    all,
		"system":   all,
		"adminTok": all,
		"token":    {"keys"}, // an admin's token without the admin scope
		// operator (otto): system.manage → system.view; its role is the
		// delegate role of every delegate() principal.
		"operator":              {"own job", "other job", "settings", "keys", "authz user", "authz role"},
		"operator files token":  {"own job", "keys", "authz user", "authz role"},
		"networker":             {"settings", "network", "mdns", "ingress", "keys", "authz role"},
		"networker files token": {"keys", "authz role"},
		"networker admin token": {"settings", "network", "mdns", "ingress", "keys", "authz role"},
		"certifier":             {"settings", "certs", "keys", "authz role"},
		"settings":              {"settings", "keys", "authz role"},
		"backupper":             {"backup", "keys", "authz role"},
		"helpdesk":              {"keys", "authz user", "authz role", "authz other"},
		"holder":                {"keys"},
	} {
		p := principals[who]
		var got []string
		for _, name := range all {
			if deliverable(p, cases[name]) {
				got = append(got, name)
			}
		}
		for _, name := range []string{"restart", "custom", "authz no data"} {
			if deliverable(p, cases[name]) {
				got = append(got, name)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s receives %v, want %v", who, got, want)
		}
	}
	for topic := range topicCaps {
		if !slices.Contains(sseServerTopics, topic) || slices.Contains(sseUserTopics, topic) {
			t.Errorf("topic %s is not subscribed as a server topic", topic)
		}
	}
}

// authz.changed reaches the accounts it concerns and holders of users.view;
// an affected stream ends right after the event (EventSource reconnects
// with the new permissions) unless only the role's groups changed.
// Recipients without users.view see no other account's id.
func TestSSEAuthzChanged(t *testing.T) {
	te := newTestEnv(t, app.ModeNetwork)
	srv := httptest.NewServer(te.handler)
	defer srv.Close()

	names := []string{"alice", "bob", "admin", "helpdesk", "holder", "networker"}
	streams := map[string]*sseClient{}
	for _, n := range names {
		streams[n] = openStream(t, srv, n)
	}
	waitSubscribers(t, te.bus, len(names))

	// received reads the authz.changed events of c until the marker (or
	// the end of the stream) and reports whether the stream is still open.
	marker := 0
	received := func(c *sseClient) (evs []core.AuthzChangedEvent, open bool) {
		t.Helper()
		want := strings.Repeat("m", marker)
		for {
			ev, ok := c.next(5 * time.Second)
			if !ok {
				return evs, false
			}
			switch ev.topic {
			case events.TopicAuthzChanged:
				var a core.AuthzChangedEvent
				if err := json.Unmarshal([]byte(ev.data), &a); err != nil {
					t.Fatalf("payload %q: %v", ev.data, err)
				}
				evs = append(evs, a)
			case events.TopicKeysState:
				if strings.Contains(ev.data, `"`+want+`"`) {
					return evs, true
				}
			}
		}
	}
	publish := func(ev core.AuthzChangedEvent) {
		marker++
		te.bus.Publish(events.Event{Topic: events.TopicAuthzChanged, Data: ev})
		te.bus.Publish(events.Event{Topic: events.TopicKeysState,
			Data: core.KeysStateEvent{State: core.KeyState(strings.Repeat("m", marker))}})
	}
	check := func(who string, wantEvents []string, wantOpen bool) {
		t.Helper()
		evs, open := received(streams[who])
		var got []string
		for _, e := range evs {
			got = append(got, e.Reason+":"+strings.Join(e.UserIDs, ","))
		}
		if !slices.Equal(got, wantEvents) || open != wantOpen {
			t.Errorf("%s: events %v open %v, want %v open %v", who, got, open, wantEvents, wantOpen)
		}
		if !open {
			delete(streams, who)
		}
	}

	// Alice's role was changed: her stream ends; bob sees nothing; the
	// people with users.view see the event and stay connected.
	publish(core.AuthzChangedEvent{UserIDs: []string{"usr_alice", "usr_bob2"}, Reason: core.AuthzRoleAssigned})
	check("alice", []string{"role_assigned:usr_alice"}, false)
	check("bob", nil, true)
	check("admin", []string{"role_assigned:usr_alice,usr_bob2"}, true)
	check("helpdesk", []string{"role_assigned:usr_alice,usr_bob2"}, true)
	check("holder", nil, true)
	check("networker", nil, true)

	// The holder's role joined a group: delivered, the stream stays.
	holderRole := principals["holder"].RoleID
	publish(core.AuthzChangedEvent{RoleID: holderRole, Reason: core.AuthzRoleGroups})
	check("holder", []string{"role_groups:"}, true)
	check("helpdesk", []string{"role_groups:"}, true)
	check("bob", nil, true)

	// The holder's role was renamed (or described, or made delegable):
	// nothing its holders may do changed, so the stream stays as well.
	publish(core.AuthzChangedEvent{RoleID: holderRole, Reason: core.AuthzRoleDetails})
	check("holder", []string{"role_details:"}, true)
	check("helpdesk", []string{"role_details:"}, true)
	check("bob", nil, true)

	// The delegate role (networker's, helpdesk's) was edited: both streams
	// end, the admin's stays.
	publish(core.AuthzChangedEvent{RoleID: principals["networker"].RoleID, Reason: core.AuthzRoleUpdated})
	check("networker", []string{"role_updated:"}, false)
	check("helpdesk", []string{"role_updated:"}, false)
	check("admin", []string{"role_groups:", "role_details:", "role_updated:"}, true)

	// The holder's role was deleted and its holders moved: the holder
	// learns about itself only.
	publish(core.AuthzChangedEvent{RoleID: holderRole, UserIDs: []string{"usr_x", "usr_rho", "usr_y"},
		Reason: core.AuthzRoleDeleted})
	check("holder", []string{"role_deleted:usr_rho"}, false)
	check("admin", []string{"role_deleted:usr_x,usr_rho,usr_y"}, true)
	check("bob", nil, true)
	waitSubscribers(t, te.bus, 2)
	for _, c := range streams { // srv.Close waits for open streams
		c.close()
	}
}
