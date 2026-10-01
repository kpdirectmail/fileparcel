package core

// Audit actions (DESIGN §9.6). Use these constants for AuditEntry.Action.
const (
	ActAuthLogin   = "auth.login"
	ActAuthLogout  = "auth.logout"
	ActAuthMFA     = "auth.mfa"
	ActAuthLockout = "auth.lockout"
	ActAuthElevate = "auth.elevate"
	ActAuthSetup   = "auth.setup"

	ActUserCreate         = "user.create"
	ActUserUpdate         = "user.update"
	ActUserDelete         = "user.delete"
	ActUserDisable        = "user.disable"
	ActUserEnable         = "user.enable"
	ActUserUnlock         = "user.unlock"
	ActUserPasswordChange = "user.password_change"
	ActUserPasswordReset  = "user.password_reset"
	ActUserMFAReset       = "user.mfa_reset"

	ActMFATOTPEnable         = "mfa.totp_enable"
	ActMFATOTPDisable        = "mfa.totp_disable"
	ActMFARecoveryRegenerate = "mfa.recovery_regenerate"
	ActPasskeyAdd            = "passkey.add"
	ActPasskeyRemove         = "passkey.remove"
	ActTokenCreate           = "token.create"
	ActTokenRevoke           = "token.revoke"
	ActSessionRevoke         = "session.revoke"

	ActInviteCreate = "invite.create"
	ActInviteRevoke = "invite.revoke"
	ActInviteAccept = "invite.accept"

	ActGroupCreate       = "group.create"
	ActGroupUpdate       = "group.update"
	ActGroupDelete       = "group.delete"
	ActGroupMemberSet    = "group.member_set"
	ActGroupMemberRemove = "group.member_remove"
	ActGroupRoleSet      = "group.role_set"    // a custom role became a member (or manager) of a group
	ActGroupRoleRemove   = "group.role_remove" // a custom role was removed from a group

	ActRoleCreate = "role.create"
	ActRoleUpdate = "role.update"
	ActRoleDelete = "role.delete"

	ActFileUpload         = "file.upload"
	ActFileDownload       = "file.download"
	ActFileRename         = "file.rename"
	ActFileMove           = "file.move"
	ActFileCopy           = "file.copy"
	ActFileTrash          = "file.trash"
	ActFileRestore        = "file.restore"
	ActFilePurge          = "file.purge"
	ActFileVersionRestore = "file.version_restore"
	ActFolderCreate       = "folder.create"
	ActGrantSet           = "grant.set"
	ActGrantRemove        = "grant.remove"
	ActArchiveDownload    = "archive.download"

	ActShareCreate       = "share.create"
	ActShareUpdate       = "share.update"
	ActShareRevoke       = "share.revoke"
	ActSharePasswordFail = "share.password_fail"
	ActRequestUpload     = "request.upload"

	ActSettingsChange = "settings.change"
	ActNetworkPolicy  = "network.policy"
	ActNetworkFunnel  = "network.funnel" // Tailscale Funnel turned on/off or changed
	ActNetworkServe   = "network.serve"  // Tailscale Serve turned on/off or changed

	ActCertRenew        = "cert.renew"
	ActCertCustomSet    = "cert.custom_set"
	ActCertCustomClear  = "cert.custom_clear"
	ActCertACME         = "cert.acme"
	ActCertTailscale    = "cert.tailscale"
	ActCARegenerate     = "ca.regenerate"
	ActClientCertIssue  = "client_cert.issue"
	ActClientCertRevoke = "client_cert.revoke"

	ActKeysUnlock         = "keys.unlock"
	ActKeysLock           = "keys.lock"
	ActKeysSeal           = "keys.seal"
	ActKeysUnseal         = "keys.unseal"
	ActKeysPassphrase     = "keys.passphrase"
	ActKeysRotate         = "keys.rotate"
	ActKeysRecoveryExport = "keys.recovery_export"

	ActBackupCreate   = "backup.create"
	ActBackupVerify   = "backup.verify"
	ActBackupDelete   = "backup.delete"
	ActBackupDownload = "backup.download"
	ActBackupImport   = "backup.import"
	ActBackupRestore  = "backup.restore"

	ActSystemStart     = "system.start"
	ActSystemStop      = "system.stop"
	ActSystemRestart   = "system.restart"
	ActAdminFileAccess = "admin.file_access"
	ActJobRun          = "job.run"
	// ActAuditReseal is recorded by the audit log itself when an unlock
	// sealed rows that were written while the keys were unavailable but not
	// by the sealing process, so their origin is not authenticated.
	ActAuditReseal = "audit.reseal"
)

// Job kinds (DESIGN §9.7).
const (
	JobUploadZip       = "upload.zip"
	JobThumbsGenerate  = "thumbs.generate"
	JobBackupCreate    = "backup.create"
	JobBackupVerify    = "backup.verify"
	JobBackupPrune     = "backup.prune"
	JobKeysRotateKEK   = "keys.rotate_kek"
	JobKeysReencrypt   = "keys.reencrypt"
	JobMaintSessions   = "maintenance.sessions"
	JobMaintUploads    = "maintenance.uploads"
	JobMaintTrash      = "maintenance.trash"
	JobMaintBlobGC     = "maintenance.blob_gc"
	JobMaintAuditPrune = "maintenance.audit_prune"
	JobMaintDBOptimize = "maintenance.db_optimize"
	JobMaintVersions   = "maintenance.versions"
	JobCertsRenewCheck = "certs.renew_check"
)

// RunnableJobKinds are the kinds an administrator may start by hand
// (POST /admin/jobs/run, GET /admin/jobs/kinds, "fileparcel jobs run"). The
// other kinds of §9.7 are started by the operation that needs them:
// upload.zip by a zip-mode upload batch, thumbs.generate after an image
// upload, keys.rotate_kek and keys.reencrypt by POST /admin/keys/rotate.
var RunnableJobKinds = []string{
	JobBackupCreate, JobBackupVerify, JobBackupPrune,
	JobMaintSessions, JobMaintUploads, JobMaintTrash, JobMaintBlobGC,
	JobMaintAuditPrune, JobMaintDBOptimize, JobMaintVersions, JobCertsRenewCheck,
}
