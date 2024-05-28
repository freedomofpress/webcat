--GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO webcat;
--GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO webcat;


CREATE TABLE types (
    id SERIAL PRIMARY KEY NOT NULL,
    value VARCHAR NOT NULL,
    description VARCHAR
);

CREATE TABLE submissions (
    id SERIAL NOT NULL PRIMARY KEY,
    submitted_fqdn VARCHAR NOT NULL,
    fqdn VARCHAR,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    policy VARCHAR,
    type_id SMALLINT NOT NULL REFERENCES types (id),
    status_id SMALLINT DEFAULT 1,
    status_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO types (value, description) VALUES ('ADD', 'New preload list submission for previously not enrolled domain.');
INSERT INTO types (value, description) VALUES ('DELETE', 'Domain removal from preload list of previously enrolled domain.');
INSERT INTO types (value, description) VALUES ('MODIFY', 'Policy change of already enrolled domain.');

CREATE TABLE statuses (
    id SERIAL PRIMARY KEY NOT NULL,
    value VARCHAR NOT NULL,
    description VARCHAR,
    completed BOOLEAN
);

-- We expect SUBMITTED to be 1 since it is set as default in submissions
INSERT INTO statuses (value, description, completed) VALUES ('SUBMITTED', 'Submission accepted in the queue.', false);
INSERT INTO statuses (value, description, completed) VALUES ('PRELIMINARY_VALIDATION_IN_PROGRESS', 'Preliminary validation in progress.', false);
INSERT INTO statuses (value, description, completed) VALUES ('PRELIMINARY_VALIDATION_ERROR', 'Preliminary validation failed.', true);
INSERT INTO statuses (value, description, completed) VALUES ('PRELIMINARY_VALIDATION_OK', 'Preliminary validation succeeded.', false);
INSERT INTO statuses (value, description, completed) VALUES ('SUBMISSION_TO_LOG_IN_PROGRESS', 'Transparency Log submission in progress.', false);
INSERT INTO statuses (value, description, completed) VALUES ('SUBMISSION_TO_LOG_ERROR', 'Transparency Log submission failed.', true);
INSERT INTO statuses (value, description, completed) VALUES ('SUBMISSION_TO_LOG_OK', 'Transparency Log submission succeded.', false);
INSERT INTO statuses (value, description, completed) VALUES ('LOG_INCLUSION_OK', 'First inclusion proof received from Transparency Log', false);
--INSERT INTO statuses (value, description, completed) VALUES ('WAITING_DELAY', 'Waiting for the set delay before sending again to the Transparency Log.', 0);
--INSERT INTO statuses (value, description, completed) VALUES ('SECOND_SUBMISSION_TO_LOG_IN_PROGRESS', 'Second Transprency Log submission in progress.', 0);
--INSERT INTO statuses (value, description, completed) VALUES ('SECOND_SUBMISSION_TO_LOG_ERROR', 'Second Transparency Log submission failed.', 1);
--INSERT INTO statuses (value, description, completed) VALUES ('SECOND_SUBMISSION_TO_LOG_OK', 'Second Transparency Log submission succeeded.', 0);
--INSERT INTO statuses (value, description, completed) VALUES ('WAITING_FOR_SECOND_PROOF', 'Waiting fot the entry to be inserted into the Transparency Log.', 0);
INSERT INTO statuses (value, description, completed) VALUES ('COMPLETED', 'Procedure succesfully completed. The Preload list has been updated.', true);

CREATE TABLE status_changes (
    id SERIAL NOT NULL PRIMARY KEY,
    submission_id INTEGER NOT NULL REFERENCES submissions (id),
    status_id SMALLINT NOT NULL REFERENCES statuses (id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE error_log (
    id SERIAL NOT NULL PRIMARY KEY,
    submission_id INTEGER NOT NULL REFERENCES submissions (id),
    status_change_id INTEGER NOT NULL REFERENCES status_changes (id),
    error VARCHAR
);

CREATE TABLE leaves (
    id SERIAL NOT NULL PRIMARY KEY,
    submission_id INTEGER NOT NULL REFERENCES submissions (id),
    leaf VARCHAR,
    hash BYTEA,
    inclusion_hashes BYTEA ARRAY,
    index INTEGER
);

CREATE TABLE list (
    id SERIAL NOT NULL PRIMARY KEY,
    fqdn VARCHAR UNIQUE,
    policy VARCHAR,
    policy_hash BYTEA,
    leaf_id INTEGER REFERENCES leaves (id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
