package blobstore

import "fileparcel/internal/settings"

// settingFsync is storage.fsync (DESIGN §11.2, owned by unit A).
const settingFsync = "storage.fsync"

func init() {
	settings.Register(settings.Def{
		Key: settingFsync, Section: "storage", Order: 90, Type: settings.TypeBool, Default: true,
		Label: "Flush file data to disk",
		Description: "fsync every uploaded part and committed file before acknowledging it. Turning it off is faster " +
			"but a power loss may lose recently uploaded files.",
	})
}
