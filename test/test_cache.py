import pytest
from time import sleep
from helpers import Browser, TorBrowser, Server, UpdateServer
import json
from pytest_check import check
from common import *
import canonicaljson
import hashlib

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    ("cases/testapp", EXPECTED_CSP | {
        "cache-control": "max-age=180"
    }, {"/console_log.png": WEBCAT_ICON}, "ERR_WEBCAT_FILE_MISMATCH"),
], indirect=["root"])
def test_in_memory_cache(browser, server: Server, update_server: UpdateServer, expected, addon_path):
    """
    Tests that an image loaded with cache headers is purged from the browser's
    in-memory cache during extension startup. Loading a corrupted file from the
    cache should not be allowed.
    """
    with server.wait_for({"/console_log.png"}):
        browser.navigate(f'{server.url()}/console_log.png')
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.navigate(f'{server.url()}/console_log.png')
    sleep(2) # loading from cache, so can't use server.wait_for
    res = browser.execute("document.body.textContent")
    assert expected in res

@pytest.mark.parametrize("browser", ["firefox", "tbb"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks", [
    ("cases/testapp", EXPECTED_CSP | {"cache-control": "max-age=180"}, FRAMEHOST_HOOK),
], indirect=["root"])
def test_cached_workers(browser, server: Server, update_server: UpdateServer, addon_path):
    """
    Tests that workers loaded from cache verify correctly. A worker that
    verifies when loaded over the network should still verify when reloaded
    from cache.
    """
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    paths_to_wait = NON_FRAME_PATHS
    if isinstance(browser, TorBrowser):
        # ServiceWorkers are disabled in TBB by NoScript
        paths_to_wait = paths_to_wait-SERVICEWORKER_PATHS
    # First navigation fetches and validates from the network and warms the
    # HTTP cache; the reload serves the worker scripts with fromCache=true
    with server.wait_for(paths_to_wait):
        browser.navigate(server.url())
    counts = {path: Server._counts.get(path, 0) for path in WORKER_PATHS}
    browser.navigate(server.url())
    sleep(4) # loading from cache, so can't use server.wait_for
    refetched = {path for path in WORKER_PATHS if Server._counts.get(path, 0) > counts[path]}
    assert refetched != WORKER_PATHS, "no worker script was served from cache"
    res = browser.execute("document.body.textContent")
    assert "Hello!" in res
    logs = json.loads(browser.execute("JSON.stringify(window.capture?.logs || [])"))
    for expected_log in [LOGENTRY_LOAD_WORKER, LOGENTRY_LOAD_SHAREDWORKER, LOGENTRY_LOAD_WASMWORKER]:
        check.is_in(expected_log, logs)

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    pytest.param("cases/testapp", EXPECTED_CSP, {
            "/": Hook(open("cases/testapp/index.html", "rb").read(), type="text/html", delay=2),
            "/js/alert.js": Hook(b"alert('hacked');", type="text/javascript"),
        }, "ERR_WEBCAT_FILE_MISMATCH",
        id="corrupted_js_with_cache_eviction_test"),
], indirect=["root"])
def test_cache_eviction(browser: Browser, server: Server, update_server: UpdateServer, expected, addon_path, dnsnames):
    """
    Tests that origin cache eviction does not interfere with verification. When
    a corrupted site is loaded while another tab simultaneously triggers cache
    eviction, the corrupted site should still be blocked.
    """
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    with server.wait_for({"/js/alert.js"}):
        browser.execute(
            "const w = window.open();"
            f"window.open('{server.url()}');"
            "setTimeout(() => {"
            f"    w.location.href = '{server.url(dnsnames[0])}/console_log.png';"
            f"    location.href = '{server.url(dnsnames[1])}/console_log.png';"
            "}, 1000)"
        )
    res = browser.execute("document.body.textContent")
    assert expected in res

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    ("cases/testapp", EXPECTED_CSP | {
        "cache-control": "max-age=180"
    }, {}, "ERR_WEBCAT_FILE_MISMATCH"),
], indirect=["root"])
def test_in_memory_cache_on_update(browser, server: Server, update_server: UpdateServer, expected, addon_path, root, non_enrolled_dnsnames):
    """
    Tests that caches are cleared on enrollment update. When an non-enrolled
    site is in the browser cache and subsequently enrolled, browser caches
    should be cleared and verification run against resources served over the
    network.
    """
    browser.install_extension(addon_path)
    update_server.reschedule(2, once=True)
    update_server.wait_for_update()

    # load a non-enrolled site into browser cache
    with server.wait_for({"/console_log.png"}):
        browser.navigate(f'{server.url(non_enrolled_dnsnames[0])}/console_log.png')

    # enroll the site
    with open(f'{root}/.well-known/webcat/bundle.json') as bundle:
        enrollment = json.load(bundle)["enrollment"]
        canonical_enrollment = canonicaljson.encode_canonical_json(enrollment)
        enrollment_hash = hashlib.sha256(canonical_enrollment).hexdigest()
        update_server.set(non_enrolled_dnsnames[0], enrollment_hash)
    
    sleep(2) # wait for the rescheduled update
    server.hooks["/console_log.png"] = WEBCAT_ICON
    with server.wait_for({"/console_log.png"}):
        browser.navigate(f'{server.url(non_enrolled_dnsnames[0])}/console_log.png')
    res = browser.execute("document.body.textContent")
    assert expected in res
