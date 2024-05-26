from flask import Flask, jsonify, request
from os import environ
from joserfc.jwk import ECKey
from joserfc import jws
from json import loads
from time import time
from string import hexdigits
from .personality import WebcatPersonality

app = Flask(__name__)

publickey = environ.get("PUBLICKEY")
database = environ.get("DATABASE_PATH")
trillian_host = environ.get("TRILLIAN_HOST")
trillian_port = environ.get("TRILLIAN_PORT")
trillian_secure = bool(environ.get("TRILLIAN_SECURE"))
trillian_credentials = environ.get("TRILLIAN_CREDENTIALS")
tree_id = environ.get("TRILLIAN_TREE_ID")

if tree_id is not None:
    tree_id = int(tree_id)

#TODO: remove hardcoding here
publickey = b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4xf6mTs3+FROqKOokO79MQ4wGHIo\nYHvI278sPt7Cwf+RGrim1q7eS9M6PlA87Vo4l14ULZI29psRYtfxbZCvNw==\n-----END PUBLIC KEY-----\n'

key = ECKey.import_key(publickey)

personality = WebcatPersonality(publickey, database, trillian_host, trillian_port, trillian_secure, trillian_credentials, tree_id)

VERSION = 1

@app.route("/")
def index():
    return jsonify({"status": "OK"})


# Only submissions really need to be authenticated, as they must come from the submission server
# that does preliminary validation. Some things are checked again here, but not as exhaustively.
@app.route(f"/v{VERSION}/queue_leaf", methods=["POST"])
def queue_submission():
    content = request.json

    if "leaf" not in content:
        return jsonify({"status": "KO", "error": "`leaf` not found in JSON body."}), 400

    leaf = content["leaf"]

    try:
        obj = jws.deserialize_compact(leaf, key)
    except:
        return jsonify({"status": "KO", "error": "Invalid signature."}), 400

    # this is probably useless, the lib already enforce this, but I've got JWT PTSD
    if obj.protected["alg"] != "ES256":
        return jsonify({"status": "KO", "error": "Invalid signature."}), 400

    try:
        payload = loads(obj.payload)
    except:
        return jsonify({"status": "KO", "error": "Invalid JSON in payload."}), 400

    if "iat" not in payload:
        return jsonify({"status": "KO", "error": "`iat` not found in payload body."}), 400

    # verify freshness
    # TODO: think of a balanced and reasonable time window
    if int(time()) - payload["iat"] > 7200:
        return jsonify({"status": "KO", "error": "The leaf submitted has expired."}), 400

    # TODO add consistency checks about the domain and the type of action (query sqlite)

    # WARNING
    # TODO: how to address malleability so that duplicates cannot be accepted? both JSON and base64url have space for malleability
    # naive approach here is to reconstruct the object manually; it probably won't be enough, no time or will to do it now
    # placeholder line
    normalized_leaf = leaf.encode("ascii")

    res = personality.queue_leaf(normalized_leaf)

    # if leaf already exist return an error and the hash
    if res.queued_leaf.status.code == 6:
        return jsonify({"status": "KO", "error": "The leaf submitted already exists.", "hash": res.queued_leaf.leaf.leaf_identity_hash.hex()}), 400

    # return the hash of the leaf queued
    return jsonify({"status": "OK", "hash": res.queued_leaf.leaf.merkle_leaf_hash.hex()})


# Lookup by hash and leave index is supported natively by Trillian. Lookup by domain is exclusive
# to this personaly and implemented separately. However, it is very convenient for domain owners to
# quickly check the status of their domain.
@app.route(f"/v{VERSION}/proof/<lookup_method>/<param>", methods=["GET"])
def proof(lookup_method, param):
    if lookup_method == "hash":
        if not all(c in hexdigits for c in param) or (len(param) % 2) != 0:
            return jsonify({"status": "KO", "error": "The hash is not a valid hex string."}), 400
        
        res = personality.get_proof_by_hash(param)
        
        if not res:
            return jsonify({"status": "KO", "error": "Proof not found, maybe it has not been merged yet."}), 404
        
        res["status"] = "OK"
        return jsonify(res)

    elif lookup_method == "index":
        try:
            index = int(param)
        except:
            return jsonify({"status": "KO", "error": "The index is not a valid integer."}), 400
        res = personality.get_proof_by_index(index)

        if not res:
            return jsonify({"status": "KO", "error": "Proof not found, maybe it has not been merged yet."}), 404
        
        res["status"] = "OK"
        return jsonify(res)

    elif lookup_method == "domain":
        pass
    elif lookup_method == "consistency":
        pass
    else:
        return jsonify({"status":"KO", "error": "Invalid `lookup_method`."}), 400

@app.route(f"/v{VERSION}/leaf/index/<index>", methods=["GET"])
def leaf(index):
    try:
        index = int(index)
    except:
        return jsonify({"status": "KO", "error": "The index is not a valid integer."}), 400
    
    res = personality.get_leaf(index)

    res["status"] = "OK"
    return jsonify(res)


@app.route(f"/v{VERSION}/root/<tree_size>", methods=["GET"])
def root(tree_size):
    # TODO: check that tree_size is lower than the one stored in sqlite
    tree_size = int(tree_size)
    log_root = personality.get_signed_log_root(tree_size)
    return jsonify({"status": "OK", "signed_log_root": log_root.to_dict()})


@app.route(f"/v{VERSION}/stats", methods=["GET"])
def stats():
    stats = personality.get_stats()
    return jsonify({"status": "OK", "stats": stats})
