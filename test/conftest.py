import os
import pytest
import json
import canonicaljson
import hashlib

from helpers import DB
from sigsum import generate_bundle

def pytest_addoption(parser):
    parser.addoption(
        "--addon", action="store", default=None,
        help="Path to the webcat test addon zip file"
    )

@pytest.fixture(scope="session")
def addon_path(request):
    raw_path = request.config.getoption("--addon")
    if not raw_path:
        pytest.exit("Error: --addon argument is required.")
    abs_path = os.path.abspath(raw_path)
    if not os.path.exists(abs_path):
        pytest.exit(f"Error: Addon path does not exist: {abs_path}")
    return abs_path

@pytest.fixture(scope="session")
def db():
    db = DB()
    db.start()
    return db

@pytest.fixture(scope="session")
def root(db, request):
    generate_bundle(request.param)
    with open(f'{request.param}/.well-known/webcat/bundle.json') as bundle:
        enrollment = json.load(bundle)["enrollment"]
        canonical_enrollment = canonicaljson.encode_canonical_json(enrollment)
        enrollment_hash = hashlib.sha256(canonical_enrollment).hexdigest()
        db.set("127.0.0.1", enrollment_hash)
    return request.param
