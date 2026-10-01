package files

import "fileparcel/internal/settings"

// Storage settings owned by unit D (DESIGN §11.2). storage.upload_* belong
// to uploads (unit E); storage.cipher and storage.fsync to blobstore (unit A).
func init() {
	settings.Register(settings.Def{Key: settingDefaultQuotaGB, Section: "storage", Order: 10,
		Type: settings.TypeInt, Default: 0, Min: 0, Max: 1 << 23,
		Label: "Default user quota (GB)",
		Description: "Storage quota of users without an individual quota, counting all versions of their files " +
			"(including the trash). 0 = unlimited."})
	settings.Register(settings.Def{Key: settingMaxFileGB, Section: "storage", Order: 20,
		Type: settings.TypeInt, Default: 0, Min: 0, Max: 1 << 23,
		Label: "Maximum file size (GB)",
		Description: "Largest single file that can be stored (a zip-on-upload counts as one file; an upload " +
			"is limited to 8 TiB per file anyway). 0 = unlimited."})
	settings.Register(settings.Def{Key: settingTrashDays, Section: "storage", Order: 40,
		Type: settings.TypeInt, Default: 30, Min: 0, Max: 3650,
		Label:       "Trash retention (days)",
		Description: "Items in the trash are deleted permanently after this many days (daily job). 0 = keep until emptied."})
	settings.Register(settings.Def{Key: settingVersionsKeep, Section: "storage", Order: 50,
		Type: settings.TypeInt, Default: 10, Min: 1, Max: 1000,
		Label:       "Versions to keep",
		Description: "Number of versions kept per file, including the current one. Older versions are deleted."})
	settings.Register(settings.Def{Key: settingZipCompression, Section: "storage", Order: 70,
		Type: settings.TypeEnum, Default: "auto", Enum: []string{"auto", "store", "deflate"},
		Label: "Zip compression",
		Description: "Compression of folder downloads and zip-on-upload: auto stores already-compressed types " +
			"(photos, videos, archives, office files) and deflates the rest."})
	settings.Register(settings.Def{Key: settingThumbnails, Section: "storage", Order: 80,
		Type: settings.TypeBool, Default: true,
		Label:       "Image thumbnails",
		Description: "Generate thumbnails (at most 320 px, stored encrypted) for JPEG, PNG, GIF, WebP and BMP images up to 50 megapixels."})
}
