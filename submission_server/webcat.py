import content_security_policy.parse
import dns.resolver
import fqdn
import logging
import psycopg2
import psycopg2.extras
import requests

from multiprocessing.pool import ThreadPool

class Submission:
    def __init__(self, submission_row):
        self.id = submission_row["id"]
        self.submitted_fqdn = submission_row["submitted_fqdn"]
        self.fqdn = submission_row["fqdn"]
        self.type_id = submission_row["type_id"]
        self.type_value = submission_row["type_value"]
        self.status_id = submission_row["status_id"]
        self.status_value = submission_row["status_value"]
        self.timestamp = submission_row["timestamp"]

        if not self.fqdn:
            if len(self.submitted_fqdn) > 255 or len(self.submitted_fqdn) < 3:
                raise ValueError("FQDN length invalid.")

            # This can raise an exception, we are supposed to catch that outside
            fqdn_object = fqdn.FQDN(self.submitted_fqdn)

            logging.info(f"Updating FQDN to normalized absolute value: {fqdn_object.absolute}.")
            self.fqdn = fqdn_object.absolute

        if self.submitted_fqdn.endswith(".onion."):
            logging.info("FQDN is a Hidden Service.")
            self.onion = True
        else:
            logging.info("FQDN is not a Hidden Service.")
            self.onion = False

        logging.info(f"Loaded submission {self.id} - {self.fqdn} - {self.type_value} - {self.status_value} - onion: {self.onion}")


class WebcatQueue:
    def __init__(self, pg_host, pg_port, pg_user, pg_password, pg_database, config, threads=10):

        self.config = config

        self.pg_connection = self.db_connect(pg_host, pg_port, pg_user, pg_password, pg_database)
        if self.pg_connection:
            self.pg_host = pg_host
            self.pg_port = pg_port
            self.pg_user = pg_user
            self.pg_password = pg_password
            self.pg_database = pg_database
        else:
            logging.error("Invalid database settings.")
            return False

        self.types = self.load_types()
        self.statuses = self.load_statuses()
        self.start()


    def update_submission(self, submission):
        cursor = self.pg_connection.cursor()
        cursor.execute("UPDATE submissions SET fqdn = %s, status_timestamp = CURRENT_TIMESTAMP WHERE id = %s", (submission.fqdn, submission.id))
        self.pg_connection.commit()
        if cursor.rowcount != 1:
            raise Exception(f"Submission {submission.id} update failed.")
        cursor.close()
        return True


    def load_types(self):
        cursor = self.pg_connection.cursor()
        cursor.execute("SELECT id, value FROM types ORDER BY id ASC")
        res = cursor.fetchall()
        types = dict()
        for row in res:
            types[row[1]] = row[0]
        cursor.close()
        return types


    def load_statuses(self):
        cursor = self.pg_connection.cursor()
        cursor.execute("SELECT id, value, completed FROM statuses ORDER BY id ASC")
        res = cursor.fetchall()
        statuses = dict()
        for row in res:
            statuses[row[1]] = row[0]
        cursor.close()
        return statuses


    def __del__(self):
        self.pg_connection.close()


    def db_connect(self, pg_host, pg_port, pg_user, pg_password, pg_database):
        try:
            connection = psycopg2.connect(user=pg_user,
                                        password=pg_password,
                                        host=pg_host,
                                        port=pg_port,
                                        database=pg_database)
            return connection

        except (Exception, psycopg2.Error) as e:
            logging.error(f"Error while fetching data from PostgreSQL {e}")
            return False

    def set_status_and_log(self, submission_id, status_id, error=None):
        cursor = self.pg_connection.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
        cursor.execute("UPDATE submissions SET status_id = %s, status_timestamp = CURRENT_TIMESTAMP WHERE id = %s;", (status_id, submission_id))
        cursor.execute("INSERT INTO status_changes (status_id, submission_id) VALUES (%s, %s) RETURNING id;", (status_id, submission_id))
        status_change_id = cursor.fetchone()["id"]
        if error:
            cursor.execute("INSERT INTO error_log (submission_id, status_change_id, error) VALUES (%s, %s, %s);", (submission_id, status_change_id, str(error)))
        self.pg_connection.commit()
        print(f"Setting status to {status_id}")
        cursor.close()


    def start(self):
        cursor = self.pg_connection.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT count(submissions.id) as count FROM submissions INNER JOIN statuses ON statuses.id=submissions.status_id WHERE completed = false;")
        count = cursor.fetchone()
        logging.info(f"Loaded {count} submissions from the queue.")

        # even if it is not particularly useful now to have a queue that just adds completed, we might want to add extra steps there
        # such as notifying website admins when the procedure is completed and stuff like that

        # note that completed should never be true if we are in a queuable status

        # if SUBMITTED -> PRELIMINARY_VALIDATION (we use the submitted fqdn)
        cursor.execute("SELECT submissions.id, fqdn, submitted_fqdn, type_id, status_id, types.value as type_value, statuses.value as status_value, timestamp, status_timestamp FROM submissions INNER JOIN statuses ON statuses.id=submissions.status_id INNER JOIN types ON types.id=submissions.type_id WHERE completed = false AND statuses.value = 'SUBMITTED';")
        self.preliminary_validation_queue = []
        for row in cursor.fetchall():
            try:
                # log the beginning of processing
                self.set_status_and_log(row["id"], self.statuses["PRELIMINARY_VALIDATION_IN_PROGRESS"], "Preliminary validation started.")
                submission = Submission(row)
                # update absolute FQDN in submission
                self.update_submission(submission)
                WebcatBasicValidator(self.config, submission)
                # TODO should we be checking for concurrent/conflicting submissions here? I would probably check later
                WebcatListValidator(self.pg_connection, submission, self.types)
                WebcatHeadersValidator(self.config, submission)
                self.set_status_and_log(row["id"], self.statuses["PRELIMINARY_VALIDATION_OK"], "Preliminary validation succeeded.")
            except Exception as error:
                # log and exit if error
                self.set_status_and_log(row["id"], self.statuses["PRELIMINARY_VALIDATION_ERROR"], error)


        # if PRELIMINARY_VALIDATION_OK -> SUBMISSION_TO_LOG
        cursor.execute("SELECT submissions.id, fqdn, type_id, status_id, statuses.value FROM submissions INNER JOIN statuses ON statuses.id=submissions.status_id WHERE completed = false AND value = 'PRELIMINARY_VALIDATION_OK';")
        for row in cursor.fetchall():
            try:
                # log the beginning of processing
                self.set_status_and_log(row["id"], self.statuses["SUBMISSION_TO_LOG_IN_PROGRESS"], "Submission to log started.")
            except Exception as error:
                self.set_status_and_log(row["id"], self.statuses["SUBMISSION_TO_LOG_ERROR"], error)

        # TODO: think if a waiting delay is really needed
        # if SUBMISSION_TO_LOG_OK -> WAITING_DELAY
        #cursor.execute("SELECT submissions.id, fqdn, type_id, status_id, statuses.value FROM submissions INNER JOIN statuses ON statuses.id=submissions.status_id WHERE completed = false AND value = 'SUBMISSION_TO_LOG_OK';")
        #self.waiting_delay_queue = cursor.fetchall()

        # if WAITING_DELAY -> SECOND_SUBMISSION_TO_LOG
        #cursor.execute("SELECT submissions.id, fqdn, type_id, status_id, statuses.value FROM submissions INNER JOIN statuses ON statuses.id=submissions.status_id WHERE completed = false AND value = 'WAITING_DELAY';")
        #self.second_submission_to_log_queue = cursor.fetchall()

        # if SECOND_SUBMISSION_TO_LOG_OK -> COMPLETED
        #cursor.execute("SELECT submissions.id, fqdn, type_id, status_id, statuses.value FROM submissions INNER JOIN statuses ON statuses.id=submissions.status_id WHERE completed = false AND value = 'SECOND_SUBMISSION_TO_LOG_OK';")
        #self.completed_queue = cursor.fetchall()

        return count["count"]


class WebcatListValidator:
    '''
    This class does:
     - Checks that there isn't an in-progress validation process for the given fqdn
     - Checks that the action type is compatible with what is already in the preload list
     -
    '''
    def __init__(self, pg_connection, submission, types):
        if not pg_connection:
            logging.error(f"{__class__}: invalid postgres connection object.")
        else:
            self.pg_connection = pg_connection

        self.submission = submission
        self.types = types
        self.check_type()

    def check_type(self):
        cursor = self.pg_connection.cursor(cursor_factory = psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT count(id) as count FROM list WHERE fqdn = %s;", (self.submission.fqdn,))
        count = cursor.fetchone()
        count = count["count"]
        # if we are doing ADD, then it must not exist in the list,
        if count == 0  and self.submission.type_id != self.types["ADD"]:
            raise Exception("An entry for {self.submission.fqdn} does not exists in the preload list. You can only ADD.")
        # if we are doing MODIFY or DELETE, then it must exist in the list
        if count == 1 and self.submission.type_id == self.types["ADD"]:
            raise Exception("An entry for {self.submission.fqdn} already exists in the preload list. You can only DELETE or MODIFY.")
        cursor.close()


class WebcatHeadersValidator:
    def __init__(self, config, submission):
        logging.info(f"Entering {__class__}")

        self.config = config
        self.submission = submission

        self.check_csp()
        self.check_sigstore()

    def check_csp(self):
        # Enforce something like this
        # Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self';
        csp = None
        for header in self.submission.headers.items():
            if header[0].lower() == "content-security-policy":
                csp = header[1]
        if not csp:
            raise Exception("No valid CSP header found.")

        # TODO: really validate it (sort, normalize, compare)
        content_security_policy.parse.policy_from_string(csp)

    def check_sigstore(self):
        sigstore_issuer = None
        sigstore_identity = None
        for header in self.submission.headers.items():
            if header[0].lower() == "x-sigstore-issuer":
                sigstore_issuer = header[1]
        for header in self.submission.headers.items():
            if header[0].lower() == "x-sigstore-identity":
                sigstore_identity = header[1]

        if not sigstore_issuer:
            raise Exception("No valid X-Sigstore-Issuer header found.")
        if not sigstore_identity:
            raise Exception("No valid X-Sigstore-Identity header found.")
        if sigstore_issuer not in self.config["sigstore_issuers"]:
            raise Exception(f"{sigstore_issuer} is not a valid OIDC issuer.")


class WebcatBasicValidator:
    '''
    This class does:
     - Checks FQDN validty
     - Normalizes FQDN
     - Classifies if onion or not
     - Check if NS and A record exists
     - Check HTTPS connection (and cert TLS validity as a consequence)

    '''
    def __init__(self, config, submission):

        self.config = config
        self.submission = submission

        self.check_dns()
        self.check_https()


    def check_dns(self):
        if not self.submission.onion:
            nameservers = dns.resolver.resolve(self.submission.fqdn, "NS")

            if len(nameservers) < 1:
                raise Exception("There is no NS record associated with this FQDN.")

            hosts = dns.resolver.resolve(self.submission.fqdn, "A")

            if len(hosts) < 1:
                raise Exception("There is no A record associated to this FQDN.")

            logging.info("DNS resolution succeded: at leats a NS and a A record exists.")

        else:
            logging.info("Skipping DNS resolution for Hidden Service.")


    def check_https(self):
        if self.submission.onion:
            # TODO, should we support TLS hidden services? Put of scope for now
            res = requests.get(f"http://{self.submission.fqdn}", headers={"User-Agent": self.config["agent"]}, proxies=self.config["tor"])
        else:
            print(self.submission.fqdn)
            res = requests.get(f"https://{self.submission.fqdn}", headers={"User-Agent": self.config["agent"]})
        self.submission.headers = res.headers


class WebcatLogSubmitter:
    def __init__(self):
        return True
