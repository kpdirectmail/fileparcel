-- 0003_zip_password.sql: password-protected zip-on-upload (DESIGN §8.1, §7.5).
-- upload_batches.zip_encryption: NULL = not protected.
-- upload_batches.zip_password_enc: Keys.SealField value, AAD
--   "upload_batches.zip_password_enc|<id>"; set to NULL as soon as the batch
--   leaves open/finalizing. Never selected by the batch API.
-- file_versions.zip_encryption: protection of that version's bytes; set only
--   by the upload.zip job (through Files.CommitFile), copied by copy/restore.
ALTER TABLE upload_batches ADD COLUMN zip_encryption TEXT
  CHECK (zip_encryption IS NULL OR zip_encryption IN ('aes256','zipcrypto'));
ALTER TABLE upload_batches ADD COLUMN zip_password_enc TEXT;
ALTER TABLE file_versions ADD COLUMN zip_encryption TEXT
  CHECK (zip_encryption IS NULL OR zip_encryption IN ('aes256','zipcrypto'));
