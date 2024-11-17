CREATE TABLE domains (
    fqdn VARCHAR(255) NOT NULL UNIQUE,
    last_hash TINYBLOB NOT NULL,
    last_action INTEGER NOT NULL
);

CREATE TABLE trillian_config (
    tree_id INTEGER NOT NULL UNIQUE
);