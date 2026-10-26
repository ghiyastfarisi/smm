-- Session and personal access tokens are stored as SHA-256 hex (see sqlstore hashToken).
-- OAuth sessions keep the raw token: it is shared with OAuthAccessData.
-- Outgoing webhook and command tokens grow to hold AES-GCM ciphertext when ENCRYPTION_KEY is set.
ALTER TABLE sessions ALTER COLUMN token TYPE VARCHAR(64);
ALTER TABLE useraccesstokens ALTER COLUMN token TYPE VARCHAR(64);
ALTER TABLE outgoingwebhooks ALTER COLUMN token TYPE VARCHAR(128);
ALTER TABLE commands ALTER COLUMN token TYPE VARCHAR(128);

UPDATE sessions SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex')
    WHERE NOT isoauth AND length(token) <> 64;
UPDATE useraccesstokens SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex')
    WHERE length(token) <> 64;
