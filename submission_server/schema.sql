-- The content of this database is not secret. The submission API returns some values of it
-- and ultimately every info here that leads to a change in the list is in the transparency log too.
-- The integrity of this database is important though: foul play here is an attack, for instance
-- it could lead to skipping certain verification phases. It is possible to detect it afterwards,
-- but still it is best if it does not happen :)
CREATE TABLE statuses (
    id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
    value VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    completed BOOLEAN
);

-- For a detailed explanation and the verification procedure see the documentation
INSERT INTO statuses (value, description, completed) VALUES ('SUBMITTED', 'Submission accepted in the queue.', false);
INSERT INTO statuses (value, description, completed) VALUES ('PRELIMINARY_VALIDATION_IN_PROGRESS', 'Preliminary validation in progress.', false);
INSERT INTO statuses (value, description, completed) VALUES ('PRELIMINARY_VALIDATION_ERROR', 'Preliminary validation failed.', true);
INSERT INTO statuses (value, description, completed) VALUES ('PRELIMINARY_VALIDATION_OK', 'Preliminary validation succeeded.', false);
INSERT INTO statuses (value, description, completed) VALUES ('SUBMISSION_TO_LOG_IN_PROGRESS', 'Transparency Log submission in progress.', false);
INSERT INTO statuses (value, description, completed) VALUES ('SUBMISSION_TO_LOG_ERROR', 'Transparency Log submission failed.', true);
INSERT INTO statuses (value, description, completed) VALUES ('SUBMISSION_TO_LOG_OK', 'Transparency Log submission succeeded.', false);
INSERT INTO statuses (value, description, completed) VALUES ('LOG_INCLUSION_OK', 'First inclusion proof received from Transparency Log', false);
INSERT INTO statuses (value, description, completed) VALUES ('WAITING_DELAY', 'Waiting for the set delay before sending again to the Transparency Log.', false);
INSERT INTO statuses (value, description, completed) VALUES ('SECOND_SUBMISSION_TO_LOG_IN_PROGRESS', 'Second Transparency Log submission in progress.', false);
INSERT INTO statuses (value, description, completed) VALUES ('SECOND_SUBMISSION_TO_LOG_ERROR', 'Second Transparency Log submission failed.', true);
INSERT INTO statuses (value, description, completed) VALUES ('SECOND_SUBMISSION_TO_LOG_OK', 'Second Transparency Log submission succeeded.', false);
INSERT INTO statuses (value, description, completed) VALUES ('WAITING_FOR_SECOND_PROOF', 'Waiting for the entry to be inserted into the Transparency Log.', false);
INSERT INTO statuses (value, description, completed) VALUES ('COMPLETED', 'Procedure successfully completed. The Preload list has been updated.', true);

CREATE TABLE submissions (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    -- Value stored raw, previous any normalization
    submitted_fqdn VARCHAR(255) NOT NULL,
    -- Normalized value
    fqdn VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    type ENUM('ADD','MODIFY','DELETE'),
    status_id INT DEFAULT 1,
    status_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (status_id) REFERENCES statuses (id)
);

-- We want to log everything that happens, to help both us and administrators to debug in case
CREATE TABLE status_changes (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    submission_id INT NOT NULL,
    status_id INT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (submission_id) REFERENCES submissions (id),
    FOREIGN KEY (status_id) REFERENCES statuses (id)
);

-- These errors are returned to everybody via the API
CREATE TABLE error_log (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    submission_id INT NOT NULL,
    status_change_id INT NOT NULL,
    error VARCHAR(255),
    FOREIGN KEY (submission_id) REFERENCES submissions (id),
    FOREIGN KEY (status_change_id) REFERENCES status_changes (id)
);

CREATE TABLE leaves (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    submission_id INT NOT NULL,
    leaf VARCHAR(255),
    hash BLOB,
    inclusion_hashes BLOB,
    `index` INT,
    FOREIGN KEY (submission_id) REFERENCES submissions (id)
);

-- This is the final list upon which 
CREATE TABLE list (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    fqdn VARCHAR(255) UNIQUE,
    policy VARCHAR(255),
    policy_hash BLOB,
    leaf_id INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (leaf_id) REFERENCES leaves (id)
);

CREATE TABLE sigstore_issuers (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    value VARCHAR(255) NOT NULL
);

INSERT INTO sigstore_issuers (name, value) VALUES ("google", "https://accounts.google.com");
INSERT INTO sigstore_issuers (name, value) VALUES ("microsoft", "https://login.microsoftonline.com");
INSERT INTO sigstore_issuers (name, value) VALUES ("github", "https://github.com/login/oauth");
INSERT INTO sigstore_issuers (name, value) VALUES ("gitlab", "https://gitlab.com");

CREATE TABLE sigstore_identities (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    identity VARCHAR(255) NOT NULL,
    issuer_id INT NOT NULL,
    FOREIGN KEY (issuer_id) REFERENCES sigstore_issuers (id)
);

CREATE TABLE policies (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    thereshold SMALLINT NOT NULL,
    submission_id INT,
    list_id INT,
    FOREIGN KEY (submission_id) REFERENCES submissions (id),
    FOREIGN KEY (list_id) REFERENCES list (id)
);

CREATE TABLE sigstore_identities_policies (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    identity_id INT NOT NULL,
    policy_id INT NOT NULL,
    FOREIGN KEY (identity_id) REFERENCES sigstore_identities (id),
    FOREIGN KEY (policy_id) REFERENCES policies (id)
);