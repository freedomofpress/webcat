from flask import Flask, jsonify, request
import os
import awsgi
from joserfc.jwk import ECKey
from joserfc import jws
from json import loads
from time import time
from string import hexdigits
from personality import WebcatPersonality, ActionTypeValue

app = Flask(__name__)

# Load environment variables
PUBLIC_KEY = os.getenv("PUBLIC_KEY")
TRILLIAN_HOST = os.getenv("TRILLIAN_HOST")
TRILLIAN_PORT = os.getenv("TRILLIAN_PORT")

DB_HOST = os.getenv("DB_HOST")
DB_PORT = int(os.getenv("DB_PORT"))
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

MAIN_DOMAIN = os.getenv("MAIN_DOMAIN")

personality = WebcatPersonality(
    PUBLIC_KEY,
    DB_HOST,
    DB_PORT,
    DB_USER,
    DB_PASSWORD,
    DB_NAME,
    TRILLIAN_HOST,
    TRILLIAN_PORT
)

VERSION = 1

def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = f"https://log.{MAIN_DOMAIN}"
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        response = jsonify({"status": "OK", "message": "CORS preflight successful"})
        response.status_code = 200
        return add_cors_headers(response)

@app.after_request
def after_request(response):
    return add_cors_headers(response)

@app.route("/")
def index():
    return jsonify({"status": "OK"})


# Only submissions really need to be authenticated, as they must come from the submission server
# that does preliminary validation. Some things are checked again here, but not as exhaustively.
@app.route(f"/v{VERSION}/queue_leaf", methods=["POST"])
def queue_submission():
    content = request.json

    if "leaf" not in content:
        return jsonify({"status": "KO", "message": "`leaf` not found in JSON body."}), 400

    leaf = content["leaf"]

    try:
        obj = jws.deserialize_compact(leaf, personality.key)
    except:
        return jsonify({"status": "KO", "message": "Invalid signature."}), 400

    # this is probably useless, the lib already enforce this, but I've got JWT PTSD
    if obj.protected["alg"] != "ES256":
        return jsonify({"status": "KO", "message": "Invalid signature."}), 400

    try:
        payload = loads(obj.payload)
    except:
        return jsonify({"status": "KO", "message": "Invalid JSON in payload."}), 400

    if "iat" not in payload:
        return jsonify({"status": "KO", "message": "`iat` not found in payload body."}), 400

    # verify freshness
    # TODO: think of a balanced and reasonable time window
    if int(time()) - payload["iat"] > 7200:
        return jsonify({"status": "KO", "message": "The leaf submitted has expired."}), 400

    try:
        fqdn = payload["fqdn"]
        action = payload["action"]
    except:
        return jsonify({"status": "KO", "message": "`fqdn` or `action` not found in payload body."}), 400

    # TODO add consistency checks about the domain and the type of action (query sqlite)
    res = personality.fqdn_db_lookup(fqdn)

    # If the domain already exists and we are trying to add it again, fail
    if res and action == ActionTypeValue.ADD:
        return jsonify({"status": "KO", "message": "`action` for the requested domain cannot be ADD because it already exists in the list.", "hash": res["last_hash"].hex()}), 400
    
    # but if we are doing something else, then the fqdn must exist
    if not res and (action == ActionTypeValue.MODIFY or action == ActionTypeValue.DELETE):
        return jsonify({"status": "KO", "message": "`action` for the requested domain cannot be DELETE or MODIFY because it does not exist in the list."}), 400

    # WARNING 💀💀💀
    # TODO: how to address malleability so that duplicates cannot be accepted? both JSON and base64url have space for malleability
    # naive approach here is to reconstruct the object manually; it probably won't be enough, no time or will to do it now
    # we must do real normalization here instead of this placeholder
    normalized_leaf = leaf.encode("ascii")

    res = personality.queue_leaf(normalized_leaf)

    # if leaf already exist return an error and the hash
    if res.queued_leaf.status.code == 6:
        return jsonify({"status": "KO", "message": "The leaf submitted already exists.", "hash": res.queued_leaf.leaf.leaf_identity_hash.hex()}), 400

    # Seems like if we are here everything's proper, let's then update the consistency db
    personality.update_list(fqdn, action, res.queued_leaf.leaf.merkle_leaf_hash)

    # return the hash of the leaf queued
    return jsonify({"status": "OK", "hash": res.queued_leaf.leaf.merkle_leaf_hash.hex()})


# Lookup by hash and leave index is supported natively by Trillian. Lookup by domain is exclusive
# to this personaly and implemented separately. However, it is very convenient for domain owners to
# quickly check the status of their domain.
@app.route(f"/v{VERSION}/proof/<lookup_method>/<param>", methods=["GET"])
def proof(lookup_method, param):
    if lookup_method == "hash":
        if not all(c in hexdigits for c in param) or (len(param) % 2) != 0:
            return jsonify({"status": "KO", "message": "The hash is not a valid hex string."}), 400
        
        res = personality.get_proof_by_hash(param)
        
        if not res:
            return jsonify({"status": "KO", "message": "Proof not found, maybe it has not been merged yet."}), 404
        
        res["status"] = "OK"
        return jsonify(res)

    elif lookup_method == "index":
        try:
            index = int(param)
        except:
            return jsonify({"status": "KO", "message": "The index is not a valid integer."}), 400
        res = personality.get_proof_by_index(index)

        if not res:
            return jsonify({"status": "KO", "message": "Proof not found, maybe it has not been merged yet."}), 404
        
        res["status"] = "OK"
        return jsonify(res)

    elif lookup_method == "domain":
        res = personality.fqdn_db_lookup(param)
        if res is None:
            return jsonify({"status": "KO", "message": "Proof not found, maybe it has not been merged yet."}), 404
        
        res = personality.get_proof_by_hash(res["last_hash"].hex())
        
        if not res:
            return jsonify({"status": "KO", "message": "Proof not found, maybe it has not been merged yet."}), 404
        
        res["status"] = "OK"
        return jsonify(res)

    elif lookup_method == "consistency":
        pass
    else:
        return jsonify({"status":"KO", "message": "Invalid `lookup_method`."}), 400


@app.route(f"/v{VERSION}/leaf/<lookup_method>/<param>", methods=["GET"])
def leaf(lookup_method, param):
    if lookup_method == "index":

        try:
            index = int(param)
        except:
            return jsonify({"status": "KO", "message": "The index is not a valid integer."}), 400
        
        try:
            res = personality.get_leaf(index)
        except:
            return jsonify({"status": "KO", "message": "Leaf not found, maybe it has not been merged yet."}), 404

        res["status"] = "OK"
        return jsonify(res)

    elif lookup_method == "hash":
        # first get the index with the hash, then lookup the object by index
        # it's silly but it's what trillian offers
        if not all(c in hexdigits for c in param) or (len(param) % 2) != 0:
            return jsonify({"status": "KO", "message": "The hash is not a valid hex string."}), 400
        
        res = personality.get_proof_by_hash(param)

        if not res:
            return jsonify({"status": "KO", "message": "Leaf not found, maybe it has not been merged yet."}), 404

        index = res["proof"]["index"]
        res = personality.get_leaf(index)

        res["status"] = "OK"
        return jsonify(res)
    elif lookup_method == "domain":
        ### TODO
        pass
    else:
        return jsonify({"status":"KO", "message": "Invalid `lookup_method`."}), 400


@app.route(f"/v{VERSION}/root", defaults={'tree_size': 0}, methods=["GET"])
@app.route(f"/v{VERSION}/root/<tree_size>", methods=["GET"])
def root(tree_size):
    # TODO: check that tree_size is lower than the one stored in sqlite
    tree_size = int(tree_size)
    try:
        output = personality.get_signed_log_root(tree_size)

        output["status"] = "OK"
        return jsonify(output)
    except:
        return jsonify({"status": "KO", "message": "`tree_size` is too large."}), 400


@app.route(f"/v{VERSION}/info", methods=["GET"])
def info():
    stats = personality.get_stats()
    return jsonify({"status": "OK", "stats": stats, "publickey": PUBLIC_KEY})

if __name__ == "__main__":
    app.run()

def lambda_handler(event, context):
    # See https://github.com/slank/awsgi/issues/73
    # TODO update to a more modern lib that as payload 2.0 support and is updated
    if 'httpMethod' not in event:
        event['httpMethod'] = event['requestContext']['http']['method']
        event['path'] = event['requestContext']['http']['path']
        event['queryStringParameters'] = event.get('queryStringParameters', {})
    return awsgi.response(app, event, context)