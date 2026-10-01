package backup

import (
	"fileparcel/internal/blobstore"
	"fileparcel/internal/core"
	"fileparcel/internal/keys"
)

// openStores opens the key service and blob store over a (temporary) home
// for deep verification (keys.Open and blobstore.New on a temporary
// core.Env, as allowed for unit H). Replaceable in tests.
var openStores = func(env *core.Env) (core.Keys, core.BlobStore, func(), error) {
	k, err := keys.Open(env)
	if err != nil {
		return nil, nil, nil, err
	}
	env.Keys = k
	b, err := blobstore.New(env)
	if err != nil {
		closeAny(k)
		return nil, nil, nil, err
	}
	return k, b, func() { closeAny(b); closeAny(k) }, nil
}
