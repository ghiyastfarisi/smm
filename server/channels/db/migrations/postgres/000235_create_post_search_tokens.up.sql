CREATE TABLE IF NOT EXISTS postsearchtokens (
    postid VARCHAR(26) NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    tokenhash CHAR(64) NOT NULL,
    PRIMARY KEY (tokenhash, postid)
);

CREATE INDEX IF NOT EXISTS idx_postsearchtokens_postid ON postsearchtokens (postid);
