-- Hashes cannot be reversed: drop what the old code could no longer match.
-- Users log in again and personal access tokens must be re-issued.
DELETE FROM sessions WHERE NOT isoauth;
DELETE FROM useraccesstokens;
