import os
import tempfile
import pytest
import json
import canonicaljson
import hashlib

from helpers import Browser, UpdateServer, Server, TorBrowser, generate_ssl_cert
from sigsum import BundleGenerator
from pytest_benchmark.fixture import BenchmarkFixture

_tbb_skips = {
    "corrupted_serviceworker_test": "ServiceWorkers not supported in Tor Browser",
    "basic_test-in_frame": "SharedWorkers in frames not supported in Tor Browser",
    "corrupted_wasm_test-in_frame": "SharedWorkers in frames not supported in Tor Browser",
    "corrupted_wasm_fetch_test-in_frame": "SharedWorkers in frames not supported in Tor Browser",
    "corrupted_wasm_worker_test-in_frame": "SharedWorkers in frames not supported in Tor Browser",
    "corrupted_sharedworker_test-in_frame": "SharedWorkers in frames not supported in Tor Browser",
    "corrupted_wasm_audioworklet_test-in_frame": "SharedWorkers in frames not supported in Tor Browser",
    "corrupted_wasm_inline_test-in_frame": "SharedWorkers in frames not supported in Tor Browser",
    "corrupted_wasm_frame_test-in_frame": "SharedWorkers in frames not supported in Tor Browser",
}
_tbb_safer_skips = {
    "basic_test": "WebAssembly not available at this security level",
    "corrupted_wasm_test": "WebAssembly not available at this security level",
    "corrupted_wasm_fetch_test": "WebAssembly not available at this security level",
    "corrupted_wasm_worker_test": "WebAssembly not available at this security level",
    "corrupted_wasm_audioworklet_test": "WebAssembly not available at this security level",
    "corrupted_wasm_inline_test": "WebAssembly not available at this security level",
    "corrupted_wasm_frame_test": "WebAssembly not available at this security level",
}
_tbb_safest_skips = {
    "no_wasm_test": "JavaScript fully disabled at this security level",
    "corrupted_js_test": "JavaScript fully disabled at this security level",
    "corrupted_worker_test": "JavaScript fully disabled at this security level",
    "corrupted_sharedworker_test": "JavaScript fully disabled at this security level",
    "corrupted_audioworklet_test": "JavaScript fully disabled at this security level",
    "corrupted_js_with_induced_error_test": "JavaScript fully disabled at this security level",
    "non_enrolled_loads_enrolled_subresource_test": "JavaScript fully disabled at this security level",
    "corrupted_js_with_cache_eviction_test": "JavaScript fully disabled at this security level",
}
_browser_skips = {
    "tbb": _tbb_skips,
    "tbb_safer": {**_tbb_skips, **_tbb_safer_skips},
    "tbb_safest": {**_tbb_skips, **_tbb_safer_skips, **_tbb_safest_skips},
}

def pytest_collection_modifyitems(items):
    for item in items:
        if not hasattr(item, "callspec"):
            continue
        browser_id = item.callspec.params.get("browser")
        skips = _browser_skips.get(browser_id, {})
        test_case = item.callspec.id.removesuffix(f"-{browser_id}")
        for pattern, reason in skips.items():
            if pattern in test_case:
                item.add_marker(pytest.mark.skip(reason=reason))

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
def dnsnames():
    return [
        "site1.localhost",
        "site2.localhost",
    ]

@pytest.fixture(scope="session")
def non_enrolled_dnsnames():
    return [
        "nonenrolled.localhost",
    ]

@pytest.fixture(scope="session")
def ssl_cert(dnsnames, non_enrolled_dnsnames):
    tmpdir = tempfile.mkdtemp()
    cert_path, key_path = generate_ssl_cert(tmpdir, dnsnames + non_enrolled_dnsnames)
    return cert_path, key_path

@pytest.fixture(scope="function")
def update_server():
    us = UpdateServer()
    us.start()
    yield us
    us.stop()

@pytest.fixture(scope="session")
def bundle_generator():
    g = BundleGenerator()
    yield g
    g.close()

@pytest.fixture(scope="session")
def root(update_server, dnsnames, request, bundle_generator):
    bundle_generator.sign(request.param)
    with open(f'{request.param}/.well-known/webcat/bundle.json') as bundle:
        enrollment = json.load(bundle)["enrollment"]
        canonical_enrollment = canonicaljson.encode_canonical_json(enrollment)
        enrollment_hash = hashlib.sha256(canonical_enrollment).hexdigest()
        update_server.set("127.0.0.1", enrollment_hash)
        for name in dnsnames:
            update_server.set(name, enrollment_hash)
    return request.param

@pytest.fixture(scope="function")
def server(root, headers, hooks, ssl_cert):
    cert_path, key_path = ssl_cert
    s = Server(
        root=root,
        headers=headers or {},
        hooks=hooks or {},
        ssl_cert=cert_path,
        ssl_key=key_path,
    )
    s.start()
    yield s
    s.stop()

@pytest.fixture(scope="function")
def browser(request, ssl_cert, server, dnsnames, non_enrolled_dnsnames):
    cert_path, _ = ssl_cert
    if request.param == "firefox":
        b = Browser()
    elif request.param == "tbb":
        b = TorBrowser(allowed_addons=["webcat@freedom.press"])
    elif request.param == "tbb_safer":
        b = TorBrowser(allowed_addons=["webcat@freedom.press"], security_level=TorBrowser.SecurityLevel.Safer)
    elif request.param == "tbb_safest":
        b = TorBrowser(allowed_addons=["webcat@freedom.press"], security_level=TorBrowser.SecurityLevel.Safest)
    else:
        raise RuntimeError(f'unrecognized browser \'{request.param}\'')
    b.trust_cert(cert_path, server.port, dnsnames + non_enrolled_dnsnames)
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
