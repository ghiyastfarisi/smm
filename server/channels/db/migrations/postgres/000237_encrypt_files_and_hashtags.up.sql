CREATE TABLE IF NOT EXISTS filesearchtokens (
    fileid VARCHAR(26) NOT NULL REFERENCES fileinfo(id) ON DELETE CASCADE,
    tokenhash CHAR(64) NOT NULL,
    PRIMARY KEY (tokenhash, fileid)
);

CREATE INDEX IF NOT EXISTS idx_filesearchtokens_fileid ON filesearchtokens (fileid);

-- Ciphertext is ~4/3 of the plaintext; varchar -> text needs no table rewrite.
ALTER TABLE posts ALTER COLUMN hashtags TYPE text;
ALTER TABLE fileinfo ALTER COLUMN name TYPE text;
