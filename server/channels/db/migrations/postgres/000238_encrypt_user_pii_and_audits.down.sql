DROP TABLE IF EXISTS usersearchtokens;
DROP INDEX IF EXISTS idx_users_emailhash_unique;
ALTER TABLE users DROP COLUMN IF EXISTS emailhash;
-- Columns stay text: encrypted values may not fit the old limits.
