package db

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestMigrationZipPassword pins 0003_zip_password: applied on top of 0002 to
// a database holding batches and versions, the old rows read NULL
// (unprotected), both zip_encryption columns take exactly NULL, "aes256"
// and "zipcrypto", and zip_password_enc holds any sealed text.
func TestMigrationZipPassword(t *testing.T) {
	ctx := context.Background()
	d := openRaw(t)
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var zip Migration
	for _, m := range ms {
		if m.Name == "zip_password" {
			zip = m
		}
	}
	if zip.Version != 3 {
		t.Fatalf("zip_password is migration %d, want 3", zip.Version)
	}
	// Everything before 0003, then data, then the rest.
	if applied, err := d.migrate(ctx, ms[:zip.Version-1]); err != nil || !slices.Equal(applied, []int{1, 2}) {
		t.Fatalf("before 0003: %v %v", applied, err)
	}
	now := Ms(time.Now())
	for _, q := range []string{
		`INSERT INTO users(id, username, role, webauthn_handle, created_at, updated_at) VALUES ('usr_m','mia','member',X'03',?1,?1)`,
		`INSERT INTO spaces(id, kind, owner_user_id, name, created_at) VALUES ('spc_u','user','usr_m','My files',?1)`,
		`INSERT INTO nodes(id, space_id, parent_id, kind, name, name_key, created_at, updated_at) VALUES
			('nod_ur','spc_u',NULL,'folder','','',?1,?1), ('nod_f','spc_u','nod_ur','file','a.zip','a.zip',?1,?1)`,
		`INSERT INTO keyring(id, purpose, mk_id, wrapped, state, created_at) VALUES ('kek_1','blob','mk_1',X'00','active',?1)`,
		`INSERT INTO blobs(id, state, size, cipher, kek_id, wrapped_dek, created_at) VALUES ('b1','ready',5,1,'kek_1',X'00',?1)`,
		`INSERT INTO file_versions(id, node_id, blob_id, size, created_at, created_by) VALUES ('ver_1','nod_f','b1',5,?1,'usr_m')`,
		`INSERT INTO upload_batches(id, user_id, folder_id, mode, zip_name, conflict, state, created_at, updated_at, expires_at)
			VALUES ('upb_1','usr_m','nod_ur','zip','Trip','rename','open',?1,?1,?1),
			       ('upb_2','usr_m','nod_ur','files',NULL,'rename','done',?1,?1,?1)`,
	} {
		if _, err := d.Exec(ctx, q, now); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	applied, err := d.Migrate(ctx)
	if err != nil || !slices.Equal(applied, []int{3, 4}) {
		t.Fatalf("migrate: %v %v", applied, err)
	}
	if got := dump(t, d, `SELECT id, coalesce(zip_encryption, 'NULL'), coalesce(zip_password_enc, 'NULL') FROM upload_batches ORDER BY id`); got != "upb_1|NULL|NULL\nupb_2|NULL|NULL" {
		t.Errorf("old batches: %s", got)
	}
	if got := dump(t, d, `SELECT id, coalesce(zip_encryption, 'NULL') FROM file_versions`); got != "ver_1|NULL" {
		t.Errorf("old versions: %s", got)
	}

	// The CHECK constraints: exactly NULL, aes256 and zipcrypto.
	for _, c := range []struct {
		table, id string
	}{{"upload_batches", "upb_1"}, {"file_versions", "ver_1"}} {
		for _, v := range []string{"aes256", "zipcrypto"} {
			if _, err := d.Exec(ctx, `UPDATE `+c.table+` SET zip_encryption = ? WHERE id = ?`, v, c.id); err != nil {
				t.Errorf("%s accepts %q: %v", c.table, v, err)
			}
		}
		if _, err := d.Exec(ctx, `UPDATE `+c.table+` SET zip_encryption = NULL WHERE id = ?`, c.id); err != nil {
			t.Errorf("%s accepts NULL: %v", c.table, err)
		}
		for _, v := range []string{"bogus", "", "AES256", "aes128"} {
			_, err := d.Exec(ctx, `UPDATE `+c.table+` SET zip_encryption = ? WHERE id = ?`, v, c.id)
			if err == nil || !strings.Contains(err.Error(), "CHECK") {
				t.Errorf("%s accepted %q (%v)", c.table, v, err)
			}
		}
	}
	// New rows are checked on INSERT too.
	if _, err := d.Exec(ctx, `INSERT INTO file_versions(id, node_id, blob_id, size, created_at, zip_encryption)
		VALUES ('ver_2','nod_f','b1',5,?1,'bogus')`, now); err == nil {
		t.Error("file_versions INSERT accepted 'bogus'")
	}
	if _, err := d.Exec(ctx, `INSERT INTO upload_batches(id, user_id, folder_id, mode, conflict, state, created_at, updated_at,
		expires_at, zip_encryption, zip_password_enc) VALUES ('upb_3','usr_m','nod_ur','zip','rename','open',?1,?1,?1,'bogus','v1:x')`, now); err == nil {
		t.Error("upload_batches INSERT accepted 'bogus'")
	}
	if _, err := d.Exec(ctx, `INSERT INTO upload_batches(id, user_id, folder_id, mode, conflict, state, created_at, updated_at,
		expires_at, zip_encryption, zip_password_enc) VALUES ('upb_3','usr_m','nod_ur','zip','rename','open',?1,?1,?1,'aes256','v1:sealed')`, now); err != nil {
		t.Errorf("protected batch: %v", err)
	}
	checkIntegrity(t, d)
}
