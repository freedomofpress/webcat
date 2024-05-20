-- Possible types of list actions
CREATE TABLE types (
    id SMALLINT PRIMARY KEY NOT NULL,
    value VARCHAR NOT NULL,
    description VARCHAR
);

-- Submission queue
-- submitted_fqdn is the raw submitted one, fqdn is the result of parsign and normalization
CREATE TABLE submissions (
    id SERIAL NOT NULL PRIMARY KEY,
    submitted_fqdn VARCHAR NOT NULL,
    fqdn VARCHAR,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    type_id SMALLINT NOT NULL REFERENCES types (id),
    status_id SMALLINT DEFAULT 0,
    status_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

--- Create the default types
INSERT INTO types (id, value, description) VALUES (0, 'ADD', 'New preload list submission for previously not enrolled domain.');
INSERT INTO types (id, value, description) VALUES (1, 'DELETE', 'Domain removal from preload list of previously enrolled domain.');
INSERT INTO types (id, value, description) VALUES (2, 'MODIFY', 'Policy change of already enrolled domain.');

--- Possible statuses of a submission
CREATE TABLE statuses (
    id SMALLINT PRIMARY KEY NOT NULL,
    value VARCHAR NOT NULL,
    description VARCHAR,
    completed BOOLEAN
);

--- Create the default statuses
--- the completed flag is crucial for processing: it defines if a status is final and no other processing is thus needed
--- TODO: we can drop a few for now
INSERT INTO statuses (id, value, description, completed) VALUES (0, 'SUBMITTED', 'Submission accepted in the queue.', 0);
INSERT INTO statuses (id, value, description, completed) VALUES (1, 'PRELIMINARY_VALIDATION_IN_PROGRESS', 'Preliminary validation in progress.', 0);
INSERT INTO statuses (id, value, description, completed) VALUES (2, 'PRELIMINARY_VALIDATION_ERROR', 'Preliminary validation failed.', 1);
INSERT INTO statuses (id, value, description, completed) VALUES (3, 'PRELIMINARY_VALIDATION_OK', 'Preliminary validation succeeded.', 0);
INSERT INTO statuses (id, value, description, completed) VALUES (4, 'SUBMISSION_TO_LOG_IN_PROGRESS', 'Transparency Log submission in progress.', 0);
INSERT INTO statuses (id, value, description, completed) VALUES (5, 'SUBMISSION_TO_LOG_ERROR', 'Transparency Log submission failed.', 1);
INSERT INTO statuses (id, value, description, completed) VALUES (6, 'SUBMISSION_TO_LOG_OK', 'Transparency Log submission succeded.', 0);
INSERT INTO statuses (id, value, description, completed) VALUES (7, 'WAITING_DELAY', 'Waiting for the set delay before sending again to the Transparency Log.', 0);
INSERT INTO statuses (id, value, description, completed) VALUES (8, 'SECOND_SUBMISSION_TO_LOG_IN_PROGRESS', 'Second Transprency Log submission in progress.', 0);
INSERT INTO statuses (id, value, description, completed) VALUES (9, 'SECOND_SUBMISSION_TO_LOG_ERROR', 'Second Transparency Log submission failed.', 1);
INSERT INTO statuses (id, value, description, completed) VALUES (10, 'SECOND_SUBMISSION_TO_LOG_OK', 'Second Transparency Log submission succeeded.', 0);
INSERT INTO statuses (id, value, description, completed) VALUES (11, 'COMPLETED', 'Procedure succesfully completed. The Preload list has been updated.', 1);

--- Table for logging all the status change events so that all history is recorded
CREATE TABLE status_changes (
    id SERIAL NOT NULL PRIMARY KEY,
    submission_id INTEGER NOT NULL REFERENCES submissions (id),
    status_id SMALLINT NOT NULL REFERENCES statuses (id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

--- Error log table
--- log any validation error here. The error log for each domain is supposed to be public
CREATE TABLE error_log (
    id SERIAL NOT NULL PRIMARY KEY,
    submission_id INTEGER NOT NULL REFERENCES submissions (id),
    status_change_id INTEGER NOT NULL REFERENCES status_changes (id),
    error VARCHAR
);

--- log submissions result to the transparency log 
--- TODO: adjust when we have a proper log implementation
CREATE TABLE transparency_log (
    id SERIAL NOT NULL PRIMARY KEY,
    submission_id INTEGER NOT NULL REFERENCES submissions (id),
    log_id INTEGER NOT NULL,
    log_link VARCHAR,
    log_proof VARCHAR
);

--- This is the reference preload list from where the bloom filter and the signed list is exported daily
--- It must be auditable via the transparency log and its status reproducible at all times
CREATE TABLE list (
    id SERIAL NOT NULL PRIMARY KEY,
    fqdn VARCHAR UNIQUE,
    policy VARCHAR,
    policy_hash BYTEA,
    log_metadata_id INTEGER REFERENCES transparency_log (id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

--- Log list changes for debug purposes mostly, auditing is done cryptographically via the log instead
CREATE TABLE list_changes (
    id SERIAL NOT NULL PRIMARY KEY,
    list_id INTEGER NOT NULL REFERENCES list (id),
    type_id SMALLINT NOT NULL REFERENCES types (id),
    submission_id INTEGER NOT NULL REFERENCES submissions (id),
    log_metadata_id INTEGER REFERENCES transparency_log (id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
