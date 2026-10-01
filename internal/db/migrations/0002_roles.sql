-- 0002_roles: custom roles ("classes"), role grants, role → group memberships
-- and the manager grant level (DESIGN §6a). users.role keeps the built-in base
-- role; users.role_id names an optional custom role (NULL = the built-in role
-- named by users.role). Applied in one transaction with foreign_keys=ON.

CREATE TABLE roles (
  id TEXT PRIMARY KEY CHECK (length(id) = 30 AND substr(id, 1, 4) = 'rol_'),
  name TEXT NOT NULL COLLATE NOCASE UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  base TEXT NOT NULL CHECK (base IN ('member','guest')),
  permissions TEXT NOT NULL DEFAULT '[]',          -- JSON array of capability names (core.Capabilities)
  delegable INTEGER NOT NULL DEFAULT 0 CHECK (delegable IN (0, 1)),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL);

-- A base change would create or delete personal spaces for every holder.
CREATE TRIGGER roles_identity_fixed BEFORE UPDATE OF id, base ON roles
WHEN NEW.id IS NOT OLD.id OR NEW.base IS NOT OLD.base
BEGIN SELECT RAISE(ABORT, 'roles: id and base cannot be changed'); END;

-- No ON DELETE action: a role that is still assigned cannot be deleted
-- (falling back to the base could give its holders more rights).
ALTER TABLE users ADD COLUMN role_id TEXT REFERENCES roles(id);
CREATE INDEX users_role_id ON users(role_id) WHERE role_id IS NOT NULL;

CREATE TRIGGER users_role_id_ins BEFORE INSERT ON users
WHEN NEW.role_id IS NOT NULL AND NEW.role IS NOT (SELECT r.base FROM roles r WHERE r.id = NEW.role_id)
BEGIN SELECT RAISE(ABORT, 'users.role must equal the base of users.role_id'); END;
CREATE TRIGGER users_role_id_upd BEFORE UPDATE OF role, role_id ON users
WHEN NEW.role_id IS NOT NULL AND NEW.role IS NOT (SELECT r.base FROM roles r WHERE r.id = NEW.role_id)
BEGIN SELECT RAISE(ABORT, 'users.role must equal the base of users.role_id'); END;

-- Not a foreign key: used/revoked invites keep the id of a deleted role for the
-- record. AcceptInvite re-resolves it and refuses when it is gone; DeleteRole
-- revokes the open invites of the role.
ALTER TABLE invites ADD COLUMN role_id TEXT;
CREATE INDEX invites_role_id ON invites(role_id) WHERE role_id IS NOT NULL;
CREATE TRIGGER invites_role_id_ins BEFORE INSERT ON invites
WHEN NEW.role_id IS NOT NULL AND NEW.role IS NOT (SELECT r.base FROM roles r WHERE r.id = NEW.role_id)
BEGIN SELECT RAISE(ABORT, 'invites.role must equal the base of invites.role_id'); END;
CREATE TRIGGER invites_role_id_upd BEFORE UPDATE OF role, role_id ON invites
WHEN NEW.role_id IS NOT NULL AND NEW.role IS NOT (SELECT r.base FROM roles r WHERE r.id = NEW.role_id)
BEGIN SELECT RAISE(ABORT, 'invites.role must equal the base of invites.role_id'); END;

-- node_grants: subject 'role' and level 'manager'. SQLite cannot alter a
-- CHECK; nothing references node_grants, so it is rebuilt with every row and id.
CREATE TABLE node_grants_v2 (id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('user','group','role')), subject_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer','editor','manager')), created_by TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER,
  UNIQUE (node_id, subject_type, subject_id));
INSERT INTO node_grants_v2 (id, node_id, subject_type, subject_id, role, created_by, created_at, expires_at)
  SELECT id, node_id, subject_type, subject_id, role, created_by, created_at, expires_at FROM node_grants;
DROP TABLE node_grants;
ALTER TABLE node_grants_v2 RENAME TO node_grants;
CREATE INDEX grants_subject ON node_grants(subject_type, subject_id);

-- Grants naming a deleted role go with it (DeleteRole also deletes them explicitly, to count them).
CREATE TRIGGER roles_delete_grants AFTER DELETE ON roles
BEGIN DELETE FROM node_grants WHERE subject_type = 'role' AND subject_id = OLD.id; END;

-- Role → group memberships: every holder of the role counts as a member (or
-- manager) of the group. Direct memberships (group_members) stay independent.
CREATE TABLE role_groups (
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  member_role TEXT NOT NULL DEFAULT 'member' CHECK (member_role IN ('member','manager')),
  added_at INTEGER NOT NULL,
  added_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  PRIMARY KEY (role_id, group_id)) WITHOUT ROWID;
CREATE INDEX role_groups_group ON role_groups(group_id);

-- Every membership, direct or through the role. A user may appear twice for one
-- group; readers that need one answer rank with
-- MAX(CASE role WHEN 'manager' THEN 2 ELSE 1 END) — never MAX(role): as
-- strings 'member' > 'manager'.
CREATE VIEW effective_group_members (group_id, user_id, role, source, via_role_id) AS
  SELECT m.group_id, m.user_id, m.role, 'direct', NULL FROM group_members m
  UNION ALL
  SELECT rg.group_id, u.id, rg.member_role, 'role', rg.role_id
  FROM role_groups rg JOIN users u ON u.role_id = rg.role_id;
