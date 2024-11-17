from enum import Enum, StrEnum
from random import randint
from trillian import LogRoot, TrillianAdminApi, TrillianApi
from joserfc.jwk import ECKey
from joserfc import jws
from json import loads
import pymysql
import os
import logging
import json

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def base64_to_pem(base64_string, pem_type="PUBLIC KEY"):
    # Insert line breaks every 64 characters
    wrapped_base64 = "\n".join(base64_string[i:i+64] for i in range(0, len(base64_string), 64))
    
    # Construct the PEM formatted string with appropriate headers and wrapped content
    pem_string = f"-----BEGIN {pem_type}-----\n{wrapped_base64}\n-----END {pem_type}-----"
    return pem_string

class ActionTypeValue(StrEnum):
        ADD = "ADD"
        DELETE = "MODIFY"
        MODIFY = "DELETE"


# The personality should check:
# - That the submitter signature is valid
# - That the submission and its corresponding action is not in conflict with the current state of the list

# Would be nice if it also provided endpoints
# - To list all the actions pertaining a domain
# - To get the most recent action for a domain

class WebcatPersonality:
    def __init__(self,
            publickey,
            db_host,
            db_port,
            db_user,
            db_password,
            db_name,
            trillian_host,
            trillian_port,
            trillian_secure=False,
            trillian_credentials=None
        ) -> None:

        self.publickey = publickey

        logging.info(f"Loading public key")
        self.key = ECKey.import_key(base64_to_pem(publickey))

        self.connection = pymysql.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            cursorclass=pymysql.cursors.DictCursor
        )
        
        with self.connection.cursor() as cursor:
            cursor.execute("SHOW DATABASES LIKE %s;", (db_name,))
            if not cursor.fetchone():
                cursor.execute(f"CREATE DATABASE `{db_name}`;")
                logging.info(f"Database '{db_name}' created.")
                self.log_id = self.create_log(trillian_host, trillian_port, trillian_secure, trillian_credentials)
                logging.info(f"Log with tree id {self.log_id} created")
                self.trillian_log = TrillianApi(trillian_host, trillian_port, self.log_id, "", trillian_secure, trillian_credentials)
                self.trillian_log.init_log()
                logging.info("Log initialized")
                

                # Switch to the new database
                self.connection.select_db(db_name)

                # Recreate the cursor after selecting the database
                with self.connection.cursor() as cursor:
                    with open("/var/task/schema.sql", "r") as schema_file:
                        schema_sql = schema_file.read()
                        for statement in schema_sql.split(';'):
                            if statement.strip():
                                cursor.execute(statement)
                        cursor.execute("INSERT INTO trillian_config (tree_id) VALUES (%s);", (self.log_id))
                        self.connection.commit()
            else:
                self.connection.select_db(db_name)
                with self.connection.cursor() as cursor:
                    cursor.execute("SELECT tree_id FROM trillian_config")
                    self.log_id = cursor.fetchone()["tree_id"]

        logging.info("Initialize completed.")


    def create_log(self, host, port, secure, credentials):
        trillian_admin = TrillianAdminApi(host, port, secure, credentials)
        logging.info("Creating tree")
        tree = trillian_admin.create_tree(display_name="WebCat Tree")
        return tree.tree_id


    def get_signed_log_root(self, first_tree_size=0) -> LogRoot:
        response = self.trillian_log.get_latest_signed_log_root(first_tree_size)
        return self.parse_proof_response(response)


    def get_tree_size(self):
        # Always check the tree size from the server, so that we can lookup on the latest tree
        response = self.get_signed_log_root()
        return response["log_root"]["tree_size"]


    def queue_leaf(self, leaf):
        return self.trillian_log.queue_leaf_raw(leaf)


    def parse_proof_response(self, response):
        # From Trillian's api.md, GetInclusionProofByHashRequest:
        # Logs can potentially contain leaves with duplicate hashes so it's possible for this to return multiple proofs.
        # If the leaf index for a particular instance of the requested Merkle leaf hash is beyond the requested tree size, 
        # the corresponding proof entry will be missing.
        
        # However, this personality should never allow this.
        # Dirty fix to handle both ByHash and ByIndex without conditions
        proof = None
        try:
            proof = response.proof[0]
        except:
            pass

        if not proof:
            try:
                proof = response.proof
            except:
                pass

        # This is to handle signedlogroot response, can have proof or not depending on first_tree_size
        log_root = LogRoot(response.signed_log_root.log_root)
        
        output = dict(log_root=log_root.to_dict())

        if proof is not None:
            proof_hashes = []
            for hash in proof.hashes:
                proof_hashes.append(hash.hex())
            output["proof"] = dict(hashes=proof_hashes, index=proof.leaf_index)

        if hasattr(response, "leaf"):
            # In this case, every leaf is a JOSE item, so we can dare and just do decode
            output["leaf"] = dict(hash=response.leaf.merkle_leaf_hash.hex(), value=response.leaf.leaf_value.decode("ascii"), timestamp=response.leaf.queue_timestamp.seconds)
            output["decoded_leaf"] = loads(jws.deserialize_compact(response.leaf.leaf_value, self.key).payload)
        return output

    def get_proof_by_hash(self, hex_hash):
        tree_size = self.get_tree_size()
        leaf_hash = bytes.fromhex(hex_hash)
        try:
            response = self.trillian_log.get_inclusion_proof_by_hash(leaf_hash, tree_size)
        except:
            return False

        return self.parse_proof_response(response)


    def get_proof_by_index(self, index):
        tree_size = self.get_tree_size()
        try:
            response = self.trillian_log.get_inclusion_proof(index, tree_size)
        except:
            return False

        return self.parse_proof_response(response)


    def get_leaf(self, index):
        tree_size = self.get_tree_size()
        response = self.trillian_log.get_entry_and_proof(index, tree_size)
        return self.parse_proof_response(response)
    

    def fqdn_db_lookup(self, fqdn):
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT fqdn, last_hash, last_action FROM domains WHERE fqdn = %s;", (fqdn,))
            res = cursor.fetchone()
        return res
    
    def update_list(self, fqdn, action, hash):
        with self.connection.cursor() as cursor:
            if action == ActionTypeValue.ADD:
                cursor.execute("INSERT INTO domains (fqdn, last_hash, last_action) VALUES (%s, %s, %s);", 
                            (fqdn, hash, ActionTypeValue.ADD))
            elif action == ActionTypeValue.MODIFY:
                cursor.execute("UPDATE domains SET last_hash = %s, last_action = %s WHERE fqdn = %s;", 
                            (hash, ActionTypeValue.MODIFY, fqdn))
            elif action == ActionTypeValue.DELETE:
                cursor.execute("DELETE FROM domains WHERE fqdn = %s;", (fqdn,))
            else:
                raise Exception("Invalid action; this should never happen.")
        self.connection.commit()
        return True

    def get_stats(self):
        tree_size = self.get_tree_size()
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(fqdn) AS count FROM domains;")
            res = cursor.fetchone()
        return dict(tree_size=tree_size, fqdn_count=res['count'])
