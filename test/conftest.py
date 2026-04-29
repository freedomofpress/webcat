import os
import pytest
import json
import canonicaljson
import hashlib

from helpers import Browser, DB, Server, TorBrowser
from sigsum import generate_bundle
from pytest_benchmark.fixture import BenchmarkFixture

def pytest_addoption(parser):
    parser.addoption(
        "--addon", action="store", default=None,
        help="Path to the webcat test addon zip file"
    )
    parser.addoption(
        "--headless", action="store_true",
        help="Run the browser in headless mode"
    )
    parser.addoption(
        "--iterations", type=int, default=20,
        help="Number of iterations per test"
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

@pytest.fixture(scope="function")
def server(root, headers, hooks):
    s = Server(
        root=root,
        headers=headers or {},
        hooks=hooks or {}
    )
    s.start()
    yield s
    s.stop()

@pytest.fixture(scope="function")
def browser(request):
    if request.param == "firefox":
        b = Browser()
    elif request.param == "tor":
        b = TorBrowser(allowed_addons=["webcat@freedom.press"])
    else:
        raise RuntimeError(f'unrecognized browser \'{request.param}\'')
    b.start(request.config.getoption("--headless"))
    yield b
    b.destroy()

class ExternallyTimedBenchmarkFixture(BenchmarkFixture):
    def _make_runner(self, function_to_benchmark, args, kwargs):
        def runner(loops_range):
            start, end, result = function_to_benchmark(loops_range, *args, **kwargs)
            return end - start, result

        return runner

@pytest.fixture
def benchmark(request):
    bs = request.config._benchmarksession
    node = request.node
    fixture = ExternallyTimedBenchmarkFixture(
        node,
        add_stats=bs.benchmarks.append,
        logger=bs.logger,
        warner=request.node.warn,
        disabled=bs.disabled,
        **dict(bs.options,
               warmup=False,
               min_rounds=123),
    )
    yield fixture
    fixture._cleanup()
