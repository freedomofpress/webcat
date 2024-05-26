from enum import Enum
from random import randint
from .trillian import LogRoot, TrillianAdminApi, TrillianApi
import sqlite3
import os
import logging
import json

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class ActionType(Enum):
        ADD = 0
        DELETE = 1
        MODIFY = 2

# The personality should check:
# - That the submitter signature is valid
# - That the submission and its corresponding action is not in conflict with the current state of the list

# Would be nice if it also provided endpoints
# - To list all the actions pertaining a domain
# - To get the most recent action for a domain

class WebcatPersonality:
    def __init__(self, publickey, database, trillian_host, trillian_port, trillian_secure=False, trillian_credentials=None, tree_id=None) -> None:
        self.publickey = publickey

        logging.info(f"Starting {__class__}")

        db_exists = os.path.isfile(database)
        logging.info(f"Trying to open sqlite database {database}.")
        self.db_connection = sqlite3.connect(database)
        self.db_cursor = self.db_connection.cursor()
        if not db_exists:
            logging.info(f"Creating new database {database}.")
            self.create_db_schema()
        
        if tree_id is None and db_exists:
            raise Exception(f"Cannot start with a Trillian log already initialized but an empty {database}.")

        if tree_id is None:
            logging.info(f"tree_id not provided, connecting to the Trillian Admin API at {trillian_host}:{trillian_port}, secure = {trillian_secure}")
            self.create_log(trillian_host, trillian_port, trillian_secure, trillian_credentials)
            tree_created = True
        else:
            self.log_id = tree_id
            tree_created = False
            
        logging.info(f"Connecting to the Trillian Log API at {trillian_host}:{trillian_port}, secure = {trillian_secure}")
        self.trillian_log = TrillianApi(trillian_host, trillian_port, self.log_id, "", trillian_secure, trillian_credentials)

        if tree_created:
            logging.info(f"Trillian tree_id {self.log_id} has been created, initializing the empty log.")
            self.trillian_log.init_log()

        logging.info(f"{__class__} init apparently successful.")


    def create_db_schema(self) -> None:
        self.db_cursor.execute("CREATE TABLE domains (fqdn TEXT NOT NULL UNIQUE, last_hash BLOB NOT NULL UNIQUE, last_index INTEGER NOT NULL UNIQUE, last_action INTEGER NOT NULL);")
        # If the validator does its job properly, and if there are no attacks, submitted must always be equal to accepted. If not, there is a consistency problem
        # in the state of the system, such as a mismatch in the list between the transparency log and the submission server
        self.db_cursor.execute("CREATE TABLE stats (tree_id INTEGER NOT NULL, tree_size INTEGER NOT NULL, submitted_count INTEGER NOT NULL, accepted_count INTEGER NOT NULL);")
        self.db_cursor.execute("INSERT INTO stats (tree_id, tree_size, submitted_count, accepted_count) VALUES (0, 0, 0, 0);")
        # There is no valid reason why a signed submission by the submission server should be rejected at this state. When that happens, something is wrong
        # and better log it somewhere to investigate.
        self.db_cursor.execute("CREATE TABLE errors (id INTEGER PRIMARY KEY AUTOINCREMENT, fqdn TEXT NOT NULL, error TEXT, input TEXT);")


    def create_log(self, host, port, secure, credentials):
        trillian_admin = TrillianAdminApi(host, port, secure, credentials)
        tree_id=randint(0, 2**32)
        logging.info(f"Creating tree with id = {tree_id}")
        tree = trillian_admin.create_tree(tree_id=tree_id, display_name="WebCat Tree")
        self.log_id = tree.tree_id


    def validate_submission(self, submission):
        pass


    def get_signed_log_root(self, first_tree_size=0) -> LogRoot:
        response = self.trillian_log.get_latest_signed_log_root(first_tree_size)
        log_root = LogRoot(response.signed_log_root.log_root)
        return log_root


    def queue_leaf(self, leaf):
        return self.trillian_log.queue_leaf_raw(leaf)


    def parse_proof_response(self, response):
        # From Trillian's api.md, GetInclusionProofByHashRequest:
        # Logs can potentially contain leaves with duplicate hashes so it's possible for this to return multiple proofs.
        # If the leaf index for a particular instance of the requested Merkle leaf hash is beyond the requested tree size, 
        # the corresponding proof entry will be missing.
        
        # However, this personality should never allow this.
        # Dirty fix to handle both ByHash and ByIndex without conditions
        try:
            proof = response.proof[0]
        except:
            proof = response.proof

        log_root = LogRoot(response.signed_log_root.log_root)
        
        proof_hashes = []
        for hash in proof.hashes:
            proof_hashes.append(hash.hex())
        
        output = dict(proof=dict(hashes=proof_hashes, index=proof.leaf_index), log_root=log_root.to_dict())

        if hasattr(response, "leaf"):
            # In this case, every leaf is a JOSE item, so we can dare and just do decode
            output["leaf"] = dict(hash=response.leaf.merkle_leaf_hash.hex(), value=response.leaf.leaf_value.decode("ascii"), timestamp=response.leaf.queue_timestamp.seconds)

        return output

    def get_proof_by_hash(self, hex_hash):
        tree_size = 4
        leaf_hash = bytes.fromhex(hex_hash)
        try:
            response = self.trillian_log.get_inclusion_proof_by_hash(leaf_hash, tree_size)
        except:
            return False

        return self.parse_proof_response(response)


    def get_proof_by_index(self, index):
        tree_size = 4
        #try:
        response = self.trillian_log.get_inclusion_proof(index, tree_size)
        #except:
        #    return False

        return self.parse_proof_response(response)


    def get_leaf(self, index):
        tree_size = 4
        response = self.trillian_log.get_entry_and_proof(index, tree_size)
        return self.parse_proof_response(response)
