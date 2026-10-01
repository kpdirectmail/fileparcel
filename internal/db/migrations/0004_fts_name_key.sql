-- 0004_fts_name_key: the search index covers nodes.name_key (DESIGN §6) instead of nodes.name.
-- The trigram tokenizer folds case one code point at a time, so over the raw name "STRASSE" did not
-- find "Straße.txt" although the two names are equal in a folder. name_key is the full case fold
-- (names.Key); search folds the query the same way, for the index and for short LIKE queries alike.

DROP TRIGGER nodes_fts_ai;
DROP TRIGGER nodes_fts_ad;
DROP TRIGGER nodes_fts_au;
DROP TABLE nodes_fts;

CREATE VIRTUAL TABLE nodes_fts USING fts5(name_key, content='nodes', content_rowid='rid', tokenize='trigram');
CREATE TRIGGER nodes_fts_ai AFTER INSERT ON nodes BEGIN
  INSERT INTO nodes_fts(rowid, name_key) VALUES (new.rid, new.name_key); END;
CREATE TRIGGER nodes_fts_ad AFTER DELETE ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name_key) VALUES ('delete', old.rid, old.name_key); END;
CREATE TRIGGER nodes_fts_au AFTER UPDATE OF name_key ON nodes BEGIN
  INSERT INTO nodes_fts(nodes_fts, rowid, name_key) VALUES ('delete', old.rid, old.name_key);
  INSERT INTO nodes_fts(rowid, name_key) VALUES (new.rid, new.name_key); END;
-- search: trigram MATCH on the folded query when it has >= 3 characters; LIKE on name_key otherwise.

INSERT INTO nodes_fts(nodes_fts) VALUES ('rebuild');
