package core

// Payloads for the standard events.Bus topics (events.Topic* constants).
// Publish them by value.

// SettingsChangedEvent is the payload of "settings.changed".
type SettingsChangedEvent struct {
	Keys []string `json:"keys"`
}

// KeysStateEvent is the payload of "keys.state".
type KeysStateEvent struct {
	State KeyState `json:"state"`
}

// JobEvent is the payload of "job.progress" and "job.done". User is the
// creator's user id ("" for system jobs; then only admins receive it).
type JobEvent struct {
	Job  *Job   `json:"job"`
	User string `json:"user,omitempty"`
}

// UploadBatchEvent is the payload of "upload.batch_done".
type UploadBatchEvent struct {
	Batch *UploadBatch `json:"batch"`
	User  string       `json:"user,omitempty"`
}

// ShareAccessedEvent is the payload of "share.accessed" (User = share owner).
type ShareAccessedEvent struct {
	Share  *Share      `json:"share"`
	Access ShareAccess `json:"access"`
	User   string      `json:"user,omitempty"`
}

// BackupEvent is the payload of "backup.finished".
type BackupEvent struct {
	Backup *Backup `json:"backup"`
}

// Reasons of an AuthzChangedEvent.
const (
	AuthzRoleAssigned = "role_assigned" // UserIDs got another role
	AuthzRoleUpdated  = "role_updated"  // the permissions of RoleID changed
	AuthzRoleDeleted  = "role_deleted"  // RoleID was deleted; UserIDs were moved to another role
	AuthzRoleGroups   = "role_groups"   // the group memberships of RoleID changed
	// AuthzRoleDetails: only the name, description or delegable flag of
	// RoleID changed — nothing its holders may do. Role lists refresh; the
	// holders' event streams stay open and they are not told their access
	// changed.
	AuthzRoleDetails = "role_details"
)

// AuthzChangedEvent is the payload of "authz.changed" (events.TopicAuthzChanged):
// the permissions of the listed users, or of every holder of RoleID, changed.
// Published by the users service after commit.
type AuthzChangedEvent struct {
	UserIDs []string `json:"user_ids,omitempty"`
	RoleID  string   `json:"role_id,omitempty"`
	Reason  string   `json:"reason"` // role_assigned | role_updated | role_deleted | role_groups | role_details
}
