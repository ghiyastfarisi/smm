ALTER TABLE users ADD COLUMN IF NOT EXISTS emailhash VARCHAR(64) NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_emailhash_unique ON users (emailhash) WHERE emailhash <> '';

CREATE TABLE IF NOT EXISTS usersearchtokens (
    userid VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tokenhash CHAR(64) NOT NULL,
    PRIMARY KEY (tokenhash, userid)
);
CREATE INDEX IF NOT EXISTS idx_usersearchtokens_userid ON usersearchtokens (userid);

-- Ciphertext is ~4/3 of the plaintext; varchar -> text needs no table rewrite.
ALTER TABLE users ALTER COLUMN email TYPE text, ALTER COLUMN nickname TYPE text,
    ALTER COLUMN firstname TYPE text, ALTER COLUMN lastname TYPE text,
    ALTER COLUMN position TYPE text, ALTER COLUMN mfasecret TYPE text;
ALTER TABLE audits ALTER COLUMN extrainfo TYPE text, ALTER COLUMN ipaddress TYPE text;
