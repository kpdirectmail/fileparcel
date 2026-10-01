#!/usr/bin/env python3
"""Phase 2: users / invites / groups admin CRUD + invite accept."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fp import *  # noqa

st = load_state()
c = admin_client()
BOB_PW = "Zephyr-Quartz-9-Meadow!x"
CAROL_PW = "Tundra-Violet-7-Ranger!x"

# ---------- cleanup from earlier runs ----------
r = c.api("GET", "/admin/users")
for u in (r.json().get("items") or []):
    if u["username"] in ("bob", "carol", "dave"):
        c.api("DELETE", "/admin/users/" + u["id"])
r = c.api("GET", "/admin/groups")
for g in (r.json().get("items") or []):
    if g["name"] == "Team Smoke":
        c.api("DELETE", "/admin/groups/" + g["id"])
r = c.api("GET", "/admin/invites")
for i in (r.json().get("items") or []):
    if i.get("status") == "active":
        c.api("DELETE", "/admin/invites/" + i["id"])
r = c.api("GET", "/admin/users")
for u in (r.json().get("items") or []):
    if u["username"] == "rita":
        c.api("DELETE", "/admin/users/" + u["id"])
r = c.api("GET", "/admin/roles")
for ro in (r.json().get("items") or []):
    if ro["name"] == "Smoke Auditors":
        c.api("DELETE", "/admin/roles/%s?reassign_to=member" % ro["id"])
r = c.api("GET", "/admin/groups")
for g in (r.json().get("items") or []):
    if g["name"] == "Smoke Roles":
        c.api("DELETE", "/admin/groups/" + g["id"])

# ---------- users ----------
r = c.api("GET", "/admin/users")
check("GET /admin/users 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("admin users lists admin", any(u["username"] == "admin" for u in r.json()["items"]), r.text()[:200])

r = c.api("POST", "/admin/users", json_body={
    "username": "bob", "display_name": "Bob", "email": "bob@example.org",
    "role": "member", "password": BOB_PW})
check("POST /admin/users (bob) 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
bob = r.json().get("user", r.json()) if r.status in (200, 201) else {}
BOB = bob.get("id", "")
check("bob has id", bool(BOB), bob)

r = c.api("GET", "/admin/users/" + BOB)
check("GET /admin/users/{id} 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

r = c.api("PATCH", "/admin/users/" + BOB, json_body={"display_name": "Bobby", "quota_bytes": 50 << 20})
check("PATCH /admin/users/{id} 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
if r.status == 200:
    u = r.json().get("user", r.json())
    check("patch applied display_name", u.get("display_name") == "Bobby", u.get("display_name"))
    check("patch applied quota", u.get("quota_bytes") == (50 << 20), u.get("quota_bytes"))

r = c.api("POST", "/admin/users/%s/disable" % BOB)
check("POST disable 200", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/admin/users/" + BOB)
check("bob disabled", r.json().get("status") == "disabled" or
      (r.json().get("user") or {}).get("status") == "disabled", r.text()[:200])
# disabled user cannot log in
cb = Client()
r = cb.api("POST", "/auth/login", json_body={"username": "bob", "password": BOB_PW})
check("disabled user cannot log in", r.status in (401, 403), "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/admin/users/%s/enable" % BOB)
check("POST enable 200", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/admin/users/%s/unlock" % BOB)
check("POST unlock 200", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))

r = c.api("GET", "/admin/users/%s/sessions" % BOB)
check("GET admin user sessions 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("DELETE", "/admin/users/%s/sessions" % BOB)
check("DELETE admin user sessions", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))

r = c.api("POST", "/admin/users/%s/password" % BOB, json_body={"password": BOB_PW, "must_change": False})
check("POST admin set password", r.status in (200, 204), "%d %s" % (r.status, r.text()[:300]))

r = c.api("POST", "/admin/users/%s/reset-mfa" % BOB)
check("POST admin reset-mfa", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))

# bob logs in
try:
    cbob = login("bob", BOB_PW)
    check("bob can log in", True)
except Exception as e:
    check("bob can log in", False, e)
    cbob = None

# bob must not reach admin routes
if cbob:
    r = cbob.api("GET", "/admin/users")
    check("member blocked from /admin/users", r.status == 403, "%d %s" % (r.status, r.text()[:200]))
    r = cbob.api("GET", "/admin/settings")
    check("member blocked from /admin/settings", r.status == 403, "%d %s" % (r.status, r.text()[:200]))

# ---------- groups ----------
r = c.api("POST", "/admin/groups", json_body={"name": "Team Smoke", "description": "integration group"})
check("POST /admin/groups 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:300]))
grp = r.json() if r.status in (200, 201) else {}
GID = grp.get("id", "")
check("group has id + space", bool(GID), grp)

r = c.api("GET", "/admin/groups")
check("GET /admin/groups 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/admin/groups/" + GID)
check("GET /admin/groups/{id} 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("PATCH", "/admin/groups/" + GID, json_body={"description": "updated"})
check("PATCH /admin/groups/{id} 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
check("group description updated", r.json().get("description") == "updated", r.text()[:200])

r = c.api("PUT", "/admin/groups/%s/members/%s" % (GID, BOB), json_body={"role": "member"})
check("PUT group member", r.status in (200, 201, 204), "%d %s" % (r.status, r.text()[:300]))
r = c.api("GET", "/admin/groups/%s/members" % GID)
check("GET group members 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("bob is a member", any(m["user_id"] == BOB for m in r.json()["items"]), r.text()[:300])

r = c.api("PUT", "/admin/groups/%s/members/%s" % (GID, BOB), json_body={"role": "manager"})
check("PUT group member -> manager", r.status in (200, 201, 204), "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/admin/groups/%s/members" % GID)
check("bob role manager", any(m["user_id"] == BOB and m["role"] == "manager" for m in r.json()["items"]), r.text()[:300])

if cbob:
    r = cbob.api("GET", "/groups")
    check("GET /groups (member view)", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    gs = r.json()
    items = gs["items"] if isinstance(gs, dict) else gs
    check("bob sees his group", any(g["id"] == GID for g in items), str(items)[:300])
    r = cbob.api("GET", "/spaces")
    sp = r.json()
    sp = sp["items"] if isinstance(sp, dict) else sp
    check("bob sees the team space", any(s.get("kind") == "group" for s in sp), str(sp)[:400])

# ---------- users lookup / activity ----------
r = c.api("GET", "/users/lookup?q=bob")
check("GET /users/lookup 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/activity")
check("GET /activity 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# ---------- invites ----------
r = c.api("POST", "/admin/invites", json_body={"email": "carol@example.org", "role": "member",
                                               "group_ids": [GID], "max_uses": 1, "note": "smoke"})
check("POST /admin/invites 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:400]))
body = r.json() if r.status in (200, 201) else {}
inv = body.get("invite") or {}
IID = inv.get("id", "")
url = body.get("url", "")
check("invite response envelope {invite,url}", bool(inv) and bool(url), list(body))
check("invite returns url", bool(url), inv)
token = url.rstrip("/").rsplit("/", 1)[-1] if url else ""
check("invite token extracted", bool(token), url)

r = c.api("GET", "/admin/invites")
check("GET /admin/invites 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# public invite view
ca = Client()
r = ca.api("GET", "/auth/invite/" + token)
check("GET /auth/invite/{token} 200", r.status == 200, "%d %s" % (r.status, r.text()[:300]))
pub = r.json() if r.status == 200 else {}
check("public invite hides token hash", "token_hash" not in pub and "url" not in pub, list(pub))
check("public invite shows role", pub.get("role") == "member", pub)

r = ca.api("GET", "/auth/invite/deadbeefdeadbeefdeadbeef")
check("bad invite token 404", r.status == 404, "%d %s" % (r.status, r.text()[:200]))

# weak password rejected on accept
r = ca.api("POST", "/auth/invite/%s/accept" % token,
           json_body={"username": "carol", "password": "short", "email": "carol@example.org"})
check("invite accept weak password 422", r.status == 422, "%d %s" % (r.status, r.text()[:200]))

r = ca.api("POST", "/auth/invite/%s/accept" % token,
           json_body={"username": "carol", "password": CAROL_PW,
                      "display_name": "Carol", "email": "carol@example.org"})
check("POST invite accept 201", r.status in (200, 201), "%d %s" % (r.status, r.text()[:400]))

r = ca.api("GET", "/me")
check("carol signed in after accept", r.status == 200 and
      (r.json().get("user") or {}).get("username") == "carol", "%d %s" % (r.status, r.text()[:200]))

r = c.api("GET", "/admin/groups/%s/members" % GID)
check("carol added to invite group",
      any(m["username"] == "carol" for m in r.json()["items"]), r.text()[:400])

# single-use invite is spent
ca2 = Client()
r = ca2.api("POST", "/auth/invite/%s/accept" % token,
            json_body={"username": "dave", "password": CAROL_PW})
check("spent invite rejected", r.status not in (200, 201), "%d %s" % (r.status, r.text()[:200]))

# revoke
r = c.api("POST", "/admin/invites", json_body={"email": "e@example.org", "role": "member"})
iid2 = (r.json().get("invite") or {}).get("id")
tok2 = r.json().get("url", "").rstrip("/").rsplit("/", 1)[-1]
r = c.api("DELETE", "/admin/invites/" + iid2)
check("DELETE /admin/invites/{id}", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))
r = Client().api("GET", "/auth/invite/" + tok2)
check("revoked invite not usable", r.status != 200, "%d %s" % (r.status, r.text()[:200]))

# ---------- group member removal + delete ----------
r = c.api("DELETE", "/admin/groups/%s/members/%s" % (GID, BOB))
check("DELETE group member", r.status in (200, 204), "%d %s" % (r.status, r.text()[:200]))

# ---------- deleting a user and a group ----------
r = c.api("POST", "/admin/users", json_body={"username": "tempuser", "generate_password": True})
check("create a throwaway user", r.status in (200, 201), "%d %s" % (r.status, r.text()[:250]))
tu = r.json()
TUID = (tu.get("user") or tu).get("id", "")
check("generated password shown once", bool(tu.get("password")), list(tu))
r = c.api("POST", "/admin/groups", json_body={"name": "Temp Group"})
TGID = r.json().get("id", "")
check("create a throwaway group", bool(TGID), r.text()[:200])
c.api("PUT", "/admin/groups/%s/members/%s" % (TGID, TUID), json_body={"role": "member"})

r = c.api("DELETE", "/admin/users/" + TUID)
check("DELETE /admin/users/{id}", r.status in (200, 204), "%d %s" % (r.status, r.text()[:250]))
r = c.api("GET", "/admin/users/" + TUID)
check("the deleted user is gone", r.status == 404, "%d" % r.status)
r = c.api("GET", "/admin/groups/%s/members" % TGID)
check("the deleted user left the group",
      not any(m["user_id"] == TUID for m in r.json()["items"]), r.text()[:250])

r = c.api("DELETE", "/admin/groups/" + TGID)
check("DELETE /admin/groups/{id}", r.status in (200, 204), "%d %s" % (r.status, r.text()[:250]))
r = c.api("GET", "/admin/groups/" + TGID)
check("the deleted group is gone", r.status == 404, "%d" % r.status)

# the last owner must not be deletable
me = c.api("GET", "/me").json()
r = c.api("DELETE", "/admin/users/" + me["user"]["id"])
check("the last owner cannot be deleted", r.status in (403, 409, 422), "%d %s" % (r.status, r.text()[:250]))
r = c.api("GET", "/me")
check("the owner still exists", r.status == 200, "%d" % r.status)

# ---------- roles and permissions (v4, DESIGN §6a) ----------
RITA_PW = "Lagoon-Amber-5-Falcon!x"
r = c.api("GET", "/admin/capabilities")
cat = r.json() if r.status == 200 else {}
check("GET /admin/capabilities 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("the catalog has 17 permissions in 5 groups",
      len(cat.get("items") or []) == 17 and len(cat.get("groups") or []) == 5,
      "%d items, %d groups" % (len(cat.get("items") or []), len(cat.get("groups") or [])))
r = c.api("GET", "/admin/roles")
check("GET /admin/roles 200", r.status == 200, "%d %s" % (r.status, r.text()[:200]))
check("the built-in roles come first", [ro["id"] for ro in (r.json().get("items") or [])[:4]] ==
      ["owner", "admin", "member", "guest"], r.text()[:300])

r = c.api("POST", "/admin/roles", json_body={
    "name": "Smoke Auditors", "description": "reads the audit log", "base": "member",
    "permissions": ["shares.links", "users.lookup", "tokens.create", "audit.view", "system.view"]})
check("POST /admin/roles 201", r.status == 201, "%d %s" % (r.status, r.text()[:300]))
role = r.json() if r.status == 201 else {}
RID = role.get("id", "")
check("the new role is custom and staff", RID.startswith("rol_") and role.get("staff") is True and
      role.get("builtin") is False, role)
r = c.api("POST", "/admin/roles", json_body={"name": "smoke auditors"})
check("a duplicate role name is 409", r.status == 409, "%d %s" % (r.status, r.text()[:200]))
r = c.api("PATCH", "/admin/roles/" + RID, json_body={"description": "audit log and dashboard"})
check("PATCH /admin/roles/{id} 200", r.status == 200 and r.json().get("description") == "audit log and dashboard",
      "%d %s" % (r.status, r.text()[:200]))
r = c.api("PATCH", "/admin/roles/member", json_body={"description": "x"})
check("built-in roles cannot be edited (422)", r.status == 422, "%d %s" % (r.status, r.text()[:200]))

# assign: create rita with the role
r = c.api("POST", "/admin/users", json_body={"username": "rita", "display_name": "Rita", "role_id": RID,
                                             "password": RITA_PW})
check("POST /admin/users with role_id 201", r.status == 201, "%d %s" % (r.status, r.text()[:300]))
rita = (r.json().get("user") or {}) if r.status == 201 else {}
RITA = rita.get("id", "")
check("rita holds the role", rita.get("role_id") == RID and rita.get("role_name") == "Smoke Auditors" and
      rita.get("role") == "member", rita)
r = c.api("GET", "/admin/users?role_id=" + RID)
check("GET /admin/users?role_id= lists the holder",
      r.status == 200 and [u["username"] for u in r.json().get("items") or []] == ["rita"], r.text()[:300])

# sign in as the holder: a staff role must set up 2FA first (auth.require_2fa=admins)
try:
    crita = login("rita", RITA_PW)
    check("rita can sign in", True)
except Exception as e:
    check("rita can sign in", False, e)
    crita = None
if crita:
    r = crita.api("GET", "/admin/audit")
    check("a staff role is gated until 2FA is set up", r.status == 403 and
          r.json()["error"]["code"] == "mfa_enroll_required", "%d %s" % (r.status, r.text()[:200]))
    r = crita.api("POST", "/me/totp/begin", json_body={})
    secret = r.json().get("secret", "") if r.status == 200 else ""
    r = crita.api("POST", "/me/totp/confirm", json_body={"code": totp_code(secret)}) if secret else r
    check("rita sets up an authenticator", r.status in (200, 201), "%d %s" % (r.status, r.text()[:200]))

    # guard checks: the role's permissions open exactly their admin areas
    r = crita.api("GET", "/me")
    me_r = r.json() if r.status == 200 else {}
    check("/me names the role and staff", me_r.get("staff") is True and
          (me_r.get("user") or {}).get("role_id") == RID and "audit.view" in ((me_r.get("user") or {}).get("permissions") or []),
          str(me_r)[:300])
    check("/me features follow the role", (me_r.get("features") or {}).get("directory") is True and
          (me_r.get("features") or {}).get("tokens") is True, me_r.get("features"))
    for path in ("/admin/audit", "/admin/dashboard", "/admin/system"):
        r = crita.api("GET", path)
        check("rita reaches GET %s" % path, r.status == 200, "%d %s" % (r.status, r.text()[:200]))
    for path, label in (("/admin/users", "View people"), ("/admin/settings", "General settings"),
                        ("/admin/backups", "Run backups")):
        r = crita.api("GET", path)
        msg = r.json().get("error", {}).get("message", "") if r.status == 403 else ""
        check("rita is refused GET %s" % path, r.status == 403 and label in msg, "%d %s" % (r.status, r.text()[:200]))
    r = crita.api("POST", "/admin/roles", json_body={"name": "Rita's own"})
    check("only administrators manage roles", r.status == 403, "%d %s" % (r.status, r.text()[:200]))
    r = crita.api("GET", "/roles")
    check("GET /roles for a role with users.lookup", r.status == 200 and
          any(x["id"] == RID for x in r.json().get("items") or []), "%d %s" % (r.status, r.text()[:200]))
if cbob:
    r = cbob.api("GET", "/roles")
    check("GET /roles for a member", r.status == 200, "%d %s" % (r.status, r.text()[:200]))

# role -> group: every holder becomes a member of Team Smoke
r = c.api("PUT", "/admin/roles/%s/groups/%s" % (RID, GID), json_body={"member_role": "member"})
check("PUT /admin/roles/{id}/groups/{groupId} 200", r.status == 200 and r.json().get("group_id") == GID,
      "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/admin/roles/%s/groups" % RID)
check("GET /admin/roles/{id}/groups lists it", r.status == 200 and
      [x["group_id"] for x in r.json().get("items") or []] == [GID], r.text()[:200])
r = c.api("GET", "/admin/groups/%s/members" % GID)
check("rita is a member through the role", any(m["user_id"] == RITA and m.get("direct") is False and
                                               (m.get("via_roles") or [{}])[0].get("id") == RID
                                               for m in r.json().get("items") or []), r.text()[:400])
if crita:
    r = crita.api("GET", "/groups")
    check("rita's /groups shows the group via the role",
          any(g["id"] == GID and g.get("via") == "role" for g in r.json().get("items") or []), r.text()[:300])

# role grant: a folder in another team folder, shared with the role
me_admin = c.api("GET", "/me").json()
ADMIN_ID = me_admin["user"]["id"]
r = c.api("POST", "/admin/groups", json_body={"name": "Smoke Roles"})
SRG = r.json() if r.status in (200, 201) else {}
c.api("PUT", "/admin/groups/%s/members/%s" % (SRG.get("id"), ADMIN_ID), json_body={"role": "manager"})
r = c.api("GET", "/spaces")
sps = r.json() if r.status == 200 else []
root = next((s["root_id"] for s in sps if s.get("id") == SRG.get("space_id")), "")
r = c.api("POST", "/nodes/%s/folders" % root, json_body={"name": "Audit Reports"})
check("a folder for the role", r.status == 201, "%d %s" % (r.status, r.text()[:200]))
FOLDER = r.json().get("id", "") if r.status == 201 else ""
r = c.api("POST", "/nodes/%s/grants" % FOLDER, json_body={"subject_type": "role", "subject_id": RID, "role": "viewer"})
check("POST /nodes/{id}/grants to a role 200", r.status == 200 and r.json().get("subject_type") == "role" and
      r.json().get("subject_name") == "Smoke Auditors", "%d %s" % (r.status, r.text()[:200]))
if crita:
    r = crita.api("GET", "/shared-with-me")
    check("rita finds the folder under Shared with me",
          any(n["id"] == FOLDER for n in r.json().get("items") or []), r.text()[:300])
r = c.api("GET", "/admin/grants?subject_type=role&subject_id=" + RID)
check("GET /admin/grants names the folder", r.status == 200 and
      [g.get("node_name") for g in r.json().get("items") or []] == ["Audit Reports"], r.text()[:300])
r = c.api("GET", "/admin/users/%s/access" % RITA)
acc = r.json() if r.status == 200 else {}
check("GET /admin/users/{id}/access", r.status == 200 and (acc.get("role") or {}).get("id") == RID and
      acc.get("staff") is True and any(g["group_id"] == GID for g in acc.get("groups") or []) and
      any(g.get("node_id") == FOLDER for g in acc.get("grants") or []), str(acc)[:400])

# delete with reassign_to
r = c.api("DELETE", "/admin/roles/" + RID)
check("deleting a role with holders needs reassign_to (409)", r.status == 409 and
      r.json()["error"].get("field") == "reassign_to", "%d %s" % (r.status, r.text()[:200]))
r = c.api("DELETE", "/admin/roles/%s?reassign_to=member" % RID)
check("DELETE /admin/roles/{id}?reassign_to=member 204", r.status == 204, "%d %s" % (r.status, r.text()[:200]))
r = c.api("GET", "/admin/users/" + RITA)
check("rita is a plain member again", r.json().get("role_id") == "member", r.text()[:200])
if crita:
    r = crita.api("GET", "/shared-with-me")
    check("the role grant went with the role",
          not any(n["id"] == FOLDER for n in r.json().get("items") or []), r.text()[:300])
    r = crita.api("GET", "/admin/audit")
    check("the audit log is closed again", r.status == 403, "%d %s" % (r.status, r.text()[:200]))

# audit entries
for action in ("role.create", "role.update", "group.role_set", "grant.set", "role.delete"):
    r = c.api("GET", "/admin/audit?action=" + action)
    check("audit has %s" % action, r.status == 200 and len(r.json().get("items") or []) >= 1,
          "%d %s" % (r.status, r.text()[:200]))

# tidy up what later phases must not see
c.api("DELETE", "/admin/users/" + RITA)
if SRG.get("id"):
    c.api("DELETE", "/admin/groups/" + SRG["id"])

st["bob"] = BOB
st["bob_pw"] = BOB_PW
st["carol_pw"] = CAROL_PW
st["group"] = GID
save_state(st)

sys.exit(1 if summary() else 0)
