import os
import shutil
import tempfile
import pytest
from time import sleep
from helpers import Browser, TorBrowser, Server, Hook, UpdateServer
import logging
import json
import canonicaljson
import hashlib
from pytest_check import check

logging.getLogger("geckordp").setLevel(logging.CRITICAL)
logging.getLogger("psutil").setLevel(logging.CRITICAL)
logging.getLogger().setLevel(logging.WARNING)

WEBCAT_ICON = Hook(
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAQAAAC1+jfqAAAABGdBTUEAALGPC/xhBQAAACBjSFJN"
    "AAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElN"
    "RQfoChYSHzod9YOfAAABNUlEQVQoz1XRv0ubARDG8c+bvMFW/BFfaAMupZWKgoPULQWXgg3orFBE"
    "cHNQ3Do46aJQFP8EB8Glg7qIOrjYuSKpguDiKNomaaEIaXw7vPZNfW457r4cd/dkNRXoUJBHXdws"
    "JsroM6Lgj0DoxqEz900gZ8KgfV8FfntiSEnZljpZMO6lNeeKlpwYVbfhvW7lZHyfT7rwzpVb0/bM"
    "I7KmPwHmlPDaqVjDN5tGQMk8tFlWwLr4IWqOvcVzKzoy8gIVL4yl5+7asSBS1ZDPCNBiRk8KjJpT"
    "MuVeIAjVMGM2/QiRCHfahaqhn35Y1Oqxjm1741oNel2kC8YavvjolU6rBv7xH1RS4LNnaLdgqjkw"
    "a9KlWOy7ojbDVkzKJS2IlR24FqsIFUV2HWn872aSP5WXU/UrcRL+AtouWZWI+tGIAAAAJXRFWHRk"
    "YXRlOmNyZWF0ZQAyMDI0LTEwLTIyVDE4OjIxOjM3KzAwOjAwXUyimQAAACV0RVh0ZGF0ZTptb2Rp"
    "ZnkAMjAyNC0xMC0yMlQxNDo1Mzo0MyswMDowMGXvS2oAAAAASUVORK5CYII=",
    type="image/png", base64=True)

BAD_WASM = Hook(
    "AGFzbQEAAAABCgJgAABgAn9/AX8DAwIAAQQFAXABAQEFBgEBggKCAgcRBAFhAgABYgAAAWMAAQFk"
    "AQAKCQICAAsEAEEACw==", type="application/wasm", base64=True)

[
    LOGENTRY_INLINE,
    LOGENTRY_ALERT,
    LOGENTRY_CSP,
    LOGENTRY_WASM_FETCH,
    LOGENTRY_WASM,
    LOGENTRY_IMPORT,
    LOGENTRY_LOAD_WORKER,
    LOGENTRY_LOAD_SHAREDWORKER,
    LOGENTRY_LOAD_WASMWORKER,
    LOGENTRY_LOAD_AUDIOWORKLET,
    LOGENTRY_WASM_FRAME,
] = EXPECTED_LOGS = [
    ["inline:",True],
    ["alert.js:",True],
    ["csp.js",True],
    ["wasm_fetch.js:",True],
    ["wasm.js:",True],
    ["import.js",True],
    ["load_worker.js:",True],
    ["load_sharedworker.js:",True],
    ["load_wasmworker.js:",True],
    ["load_audioworklet.js:",True],
    ["wasm_frame.js:",True],
]

EXPECTED_CSP = {
    "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval' "
                               "'sha256-oiHtO61BAW24D+FpLSqz2Jnv6Wv67XDn90HOTlaklfQ='; "
                               "style-src 'self'; frame-src 'none'; worker-src 'self';"
}

FRAMEHOST_HOOK = {
    "/framehost.html": Hook(open("cases/testapp/framehost.html", "rb").read(), type="text/html", headers={
        "content-security-policy": "",
    }),
}

CSS_PATHS = set(map(lambda filename: f"/css/{filename}", os.listdir("./cases/testapp/css/")))
JS_PATHS = set(map(lambda filename: f"/js/{filename}", os.listdir("./cases/testapp/js/")))
WASM_PATHS = set(map(lambda filename: f"/wasm/{filename}", os.listdir("./cases/testapp/wasm/")))
WORKER_PATHS = set(map(lambda filename: f"/workers/{filename}", os.listdir("./cases/testapp/workers/")))
FRAME_PATHS = {"/js/framehost.js", "/wasm/frame_addThree.wasm"}
ALL_PATHS = set().union(CSS_PATHS,JS_PATHS,WASM_PATHS,WORKER_PATHS)
NON_FRAME_PATHS = ALL_PATHS-FRAME_PATHS

def setdiff(a: list, b: list):
    a = a.copy()
    for el in b:
        try:
            a.remove(el)
        except:
            pass
    return a

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("in_frame", [False, True], ids=["plain","in_frame"])
@pytest.mark.parametrize("root, headers, hooks, expected, logs, errors, rejections, paths_to_wait", [

    # Basic correct execution
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK, "Hello!", EXPECTED_LOGS, [], [], NON_FRAME_PATHS,
        id="basic_test"),

    # Correct execution without WebAssembly or Workers
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {
            "/js/wasm.js": b"",
            "/js/wasm_fetch.js": b"",
            "/js/load_worker.js": b"",
            "/js/load_sharedworker.js": b"",
            "/js/load_wasmframe.js": b"",
            "/js/load_wasmworker.js": b"",
            "/js/load_audioworklet.js": b"",
            "/wasm/inline_addTwo.wasm": Hook(b"", delay=5),
        }, "Hello!", setdiff(
            EXPECTED_LOGS, [
                LOGENTRY_WASM,
                LOGENTRY_WASM_FETCH,
                LOGENTRY_LOAD_WORKER,
                LOGENTRY_LOAD_SHAREDWORKER,
                LOGENTRY_WASM_FRAME,
                LOGENTRY_LOAD_WASMWORKER,
                LOGENTRY_LOAD_AUDIOWORKLET,
                LOGENTRY_INLINE,
            ]), [], [],
        NON_FRAME_PATHS-WASM_PATHS-WORKER_PATHS-{"/js/wasm_frame.js"},
        id="no_wasm_test"),

    # Wrong CSP
    pytest.param("cases/testapp", {
            "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                    "style-src 'self'; frame-src 'none'; worker-src 'self';"
        }, FRAMEHOST_HOOK, "ERR_WEBCAT_CSP_MISMATCH", [], [], [], {"/"},
        id="wrong_csp_test"),

    # Missing CSP
    pytest.param("cases/testapp", {
            # No CSP header
        }, FRAMEHOST_HOOK, "ERR_WEBCAT_HEADERS_MISSING_CRITICAL", [], [], [], {"/"},
        id="missing_csp_test"),

    # Hook / with static content
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/": b"<html><body>replaced index</body></html>"}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/"},
        id="corrupted_index_test"),

    # Hook /.well-known/webcat/bundle.json
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/.well-known/webcat/bundle.json": b'{"a":"b"}'}, "ERR_WEBCAT_BUNDLE_MISSING_ENROLLMENT", [], [], [], {"/"},
        id="corrupted_manifest_test"),

    # Hook /js/alert.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/js/alert.js": b"alert('hacked');"}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/js/alert.js"},
        id="corrupted_js_test"),

    # Hook /wasm/addTwo.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/addTwo.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_WASM]), [], [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
        ], NON_FRAME_PATHS,
        id="corrupted_wasm_test"),

    # Hook /wasm/addThree.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/addThree.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_WASM_FETCH]), [], [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
        ], NON_FRAME_PATHS,
        id="corrupted_wasm_fetch_test"),

    # Hook /wasm/reverseSub.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/reverseSub.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_LOAD_WASMWORKER]), [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '/workers/wasm_worker.js']
        ], [], NON_FRAME_PATHS,
        id="corrupted_wasm_worker_test"),

    # Hook /workers/worker.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/workers/worker.js": Hook(b"console.log('hacked');", "text/javascript")}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/workers/worker.js"},
        id="corrupted_worker_test"),

    # Hook /workers/sharedworker.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/workers/sharedworker.js": Hook(b"console.log('hacked');", "text/javascript")}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/workers/sharedworker.js"},
        id="corrupted_sharedworker_test"),

    # Hook /workers/serviceworker.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/workers/serviceworker.js": Hook(b"console.log('hacked');", "text/javascript")}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/workers/serviceworker.js"},
        id="corrupted_serviceworker_test"),

    # Hook /workers/audioworklet.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/workers/audioworklet.js": Hook(b"console.log('hacked');", "text/javascript")}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/workers/audioworklet.js"},
        id="corrupted_audioworklet_test"),
    
    # Hook /wasm/aw_addTwo.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/aw_addTwo.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_LOAD_AUDIOWORKLET]), [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '/workers/audioworklet.js']
        ], [], NON_FRAME_PATHS,
        id="corrupted_wasm_audioworklet_test"),

    # Hook /wasm/inline_addTwo.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/inline_addTwo.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_INLINE]), [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
        ], [], NON_FRAME_PATHS,
        id="corrupted_wasm_inline_test"),

    # Hook /wasm/frame_addThree.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/frame_addThree.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_WASM_FRAME]), [], [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
        ], NON_FRAME_PATHS,
        id="corrupted_wasm_frame_test"),

], indirect=["root"])
def test_webcat(browser, in_frame, server: Server, update_server: UpdateServer, expected, logs, errors, rejections, paths_to_wait, addon_path, dnsnames, non_enrolled_dnsnames):
    logs, errors, rejections = logs.copy(), errors.copy(), rejections.copy()
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    if in_frame:
        browser.navigate(f"{server.url(non_enrolled_dnsnames[0])}/framehost.html?url={server.url(dnsnames[0])}")
    else:
        browser.navigate(server.url())
    if isinstance(browser, TorBrowser):
        server.wait_for(paths_to_wait-{"/workers/serviceworker.js"})
    else:      
        server.wait_for(paths_to_wait)
    if not in_frame:
        res = browser.execute("document.body.innerText")
        assert expected in res
    res = json.loads(browser.execute("JSON.stringify(window.capture?.logs || [])"))
    for log in res:
        if check.is_in(log, logs, "Actual log entry should be present in expected logs"):
            logs.remove(log)
    for log in logs:
        check.is_none(log, "Expected log entry should be present in actual logs")
    res = json.loads(browser.execute("JSON.stringify(window.capture?.errors || [])"))
    for err in res:
        if check.is_in(err, errors, "Actual error should be present in expected errors"):
            errors.remove(err)
    for err in errors:
        check.is_none(err, "Expected error should be present in actual errors")
    res = json.loads(browser.execute("JSON.stringify(window.capture?.rejections || [])"))
    for err in res:
        if check.is_in(err, rejections, "Actual rejection should be present in expected rejections"):
            rejections.remove(err)
    for err in rejections:
        check.is_none(err, "Expected rejection should be present in actual rejections")

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    ("cases/testapp", EXPECTED_CSP | {
        "cache-control": "max-age=180"
    }, {"/console_log.png": WEBCAT_ICON}, "ERR_WEBCAT_FILE_MISMATCH"),
], indirect=["root"])
def test_in_memory_cache(browser, server: Server, update_server: UpdateServer, expected, addon_path):
    browser.navigate(f'{server.url()}/console_log.png')
    server.wait_for({"/favicon.ico"})
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.navigate(f'{server.url()}/console_log.png')
    sleep(2) # loading from cache, so can't use server.wait_for
    res = browser.execute("document.body.innerText")
    assert expected in res

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    pytest.param("cases/testapp", EXPECTED_CSP, {
            "/": Hook(open("cases/testapp/index.html", "rb").read(), type="text/html", delay=2),
            "/js/alert.js": Hook(b"alert('hacked');", type="text/javascript"),
            "/x": Hook(b"", type="text/html", headers={"refresh": "0"}),
        }, "ERR_WEBCAT_FILE_MISMATCH",
        id="corrupted_js_with_induced_error_test"),
], indirect=["root"])
def test_multiple_tabs(browser: Browser, server: Server, update_server: UpdateServer, expected, addon_path):
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.execute(
        f"window.open('{server.url()}');"
        f"setTimeout(() => location.href = '{server.url()}/x', 1000)"
    )
    server.wait_for({"/js/alert.js"})
    res = browser.execute("document.body.innerText")
    assert expected in res

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    pytest.param("cases/testapp", EXPECTED_CSP, {
            "/js/alert.js": Hook(b"alert('hacked');", type="text/javascript"),
        }, "ERR_WEBCAT_FILE_MISMATCH",
        id="non_enrolled_loads_enrolled_subresource_test"),
], indirect=["root"])
def test_non_enrolled_subresource(browser: Browser, server: Server, update_server: UpdateServer, expected, addon_path, dnsnames, non_enrolled_dnsnames):
    enrolled_url = server.url(dnsnames[0])
    non_enrolled_url = server.url(non_enrolled_dnsnames[0])
    # Non-enrolled landing page that loads a single sub-resource cross-origin
    # from the enrolled domain.
    server.hooks["/"] = Hook(
        b'<!DOCTYPE html><html><body>'
        b'<p>non-enrolled</p>'
        b'<script src="' + enrolled_url.encode() + b'/js/alert.js"></script>'
        b'</body></html>',
        type="text/html",
        headers={"content-security-policy": "script-src *"},
    )
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.navigate(non_enrolled_url)
    server.wait_for({"/js/alert.js"})
    res = browser.execute("document.body.innerText")
    assert expected in res

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    pytest.param("cases/testapp", EXPECTED_CSP, {
            "/": Hook(open("cases/testapp/index.html", "rb").read(), type="text/html", delay=2),
            "/js/alert.js": Hook(b"alert('hacked');", type="text/javascript"),
        }, "ERR_WEBCAT_FILE_MISMATCH",
        id="corrupted_js_with_cache_eviction_test"),
], indirect=["root"])
def test_cache_eviction(browser: Browser, server: Server, update_server: UpdateServer, expected, addon_path, dnsnames):
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.execute(
         "const w = window.open();"
        f"window.open('{server.url()}');"
         "setTimeout(() => {"
        f"    w.location.href = '{server.url(dnsnames[0])}/console_log.png';"
        f"    location.href = '{server.url(dnsnames[1])}/console_log.png';"
         "}, 1000)"
    )
    server.wait_for({"/js/alert.js"})
    res = browser.execute("document.body.innerText")
    assert expected in res

@pytest.mark.parametrize("browser, paths_to_wait", [
    pytest.param("firefox", NON_FRAME_PATHS, id="firefox"),
    pytest.param("tbb", NON_FRAME_PATHS-{"/workers/serviceworker.js"}, id="tbb"),
    pytest.param("tbb_safer", NON_FRAME_PATHS-{"/workers/serviceworker.js"}-WASM_PATHS, id="tbb_safer"),
    pytest.param("tbb_safest", NON_FRAME_PATHS-JS_PATHS-WORKER_PATHS-WASM_PATHS, id="tbb_safest")
], indirect=["browser"])
@pytest.mark.parametrize("root, headers, hooks, delegated_fqdn, should_verify", [
    # site2.localhost shares the same enrollment_hash as site1.localhost
    pytest.param("cases/testapp",
        EXPECTED_CSP | {"x-webcat-delegation": "site2.localhost"},
        FRAMEHOST_HOOK,
        "site2.localhost", True,
        id="delegation_accepted_test"),

    # nonenrolled.localhost is not in the enrollment DB, so verifyDelegation rejects.
    # Page still loads, but no delegation appears in the log.
    pytest.param("cases/testapp",
        EXPECTED_CSP | {"x-webcat-delegation": "nonenrolled.localhost"},
        FRAMEHOST_HOOK,
        "nonenrolled.localhost", False,
        id="delegation_rejected_test"),
], indirect=["root"])
def test_delegation(browser: Browser, server: Server, update_server: UpdateServer, delegated_fqdn, should_verify, paths_to_wait, addon_path, dnsnames):
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    # Subscribe before navigation so we don't miss the "Setting ok icon" line
    browser.attach_extension_console()
    browser.navigate(f"{server.url(dnsnames[0])}/")
    server.wait_for(paths_to_wait)

    # Page loads successfully in both cases
    assert "Hello!" in browser.execute("document.body.innerText")

    logs_blob = json.dumps(browser.extension_logs())
    accepted_marker = f"Setting ok icon (delegation: {delegated_fqdn})"
    if should_verify:
        assert accepted_marker in logs_blob, (
            f"expected delegation marker {accepted_marker!r} in extension logs, got: {logs_blob}"
        )
    else:
        assert accepted_marker not in logs_blob, (
            f"delegation to non-enrolled {delegated_fqdn!r} should not have been accepted: {logs_blob}"
        )
        # And the unadorned ok-icon log should still be present.
        assert "Setting ok icon" in logs_blob, logs_blob

@pytest.mark.parametrize("browser, paths_to_wait", [
    pytest.param("firefox", NON_FRAME_PATHS, id="firefox"),
    pytest.param("tbb", NON_FRAME_PATHS-{"/workers/serviceworker.js"}, id="tbb"),
    pytest.param("tbb_safer", NON_FRAME_PATHS-{"/workers/serviceworker.js"}-WASM_PATHS, id="tbb_safer"),
    pytest.param("tbb_safest", NON_FRAME_PATHS-JS_PATHS-WORKER_PATHS-WASM_PATHS, id="tbb_safest")
], indirect=["browser"])
@pytest.mark.parametrize("root, headers, hooks, expected", [
    pytest.param("cases/testapp", EXPECTED_CSP, {}, "Hello v2!",
        id="version_refresh_test"),
], indirect=["root"])
def test_version_refresh(browser: Browser, server: Server, update_server: UpdateServer, bundle_generator, expected, paths_to_wait, addon_path, root):
    # Load v0.1: server serves the bundle that the `root` fixture signed.
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.navigate(server.url())
    server.wait_for(paths_to_wait)
    assert "Hello!" in browser.execute("document.body.innerText")

    # Build a v0.2 bundle signed with the same enrollment as v0.1, with a
    # modified index.html. The inline <script> block is left untouched so its
    # CSP sha256 hash stays valid.
    with tempfile.TemporaryDirectory() as tmp:
        v2_dir = os.path.join(tmp, "testapp_v2")
        shutil.copytree(root, v2_dir)
        index_path = os.path.join(v2_dir, "index.html")
        with open(index_path, "r", encoding="utf-8") as f:
            html = f.read()
        new_html = html.replace("<p>Hello!</p>", "<p>Hello v2!</p>")
        assert new_html != html, "index.html marker not found"
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(new_html)
        config_path = os.path.join(v2_dir, "webcat.config.json")
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        config["version"] = "0.2"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f)
        v2_bundle_path = os.path.join(tmp, "bundle_v2.json")
        bundle_generator.sign(v2_dir, output_path=v2_bundle_path)
        with open(v2_bundle_path, "rb") as f:
            v2_bundle = f.read()
        with open(index_path, "rb") as f:
            v2_index = f.read()

    # Server now signals a new version and serves the v0.2 bundle + content.
    # The extension should detect x-webcat-version > cached manifest.version,
    # purge the origin cache and browser caches, and reload.
    server.hooks["/"] = Hook(v2_index, type="text/html",
                             headers={"x-webcat-version": "0.2"})
    server.hooks["/.well-known/webcat/bundle.json"] = Hook(
        v2_bundle, type="application/json",
        headers={"cache-control": "no-store"})

    browser.execute("location.reload()")
    server.wait_for(paths_to_wait)
    assert expected in browser.execute("document.body.innerText")

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    ("cases/testapp", EXPECTED_CSP | {
        "cache-control": "max-age=180"
    }, {}, "ERR_WEBCAT_FILE_MISMATCH"),
], indirect=["root"])
def test_in_memory_cache_on_update(browser, server: Server, update_server: UpdateServer, expected, addon_path, root, non_enrolled_dnsnames):
    browser.install_extension(addon_path)
    update_server.reschedule(2, once=True)
    update_server.wait_for_update()

    # load a non-enrolled site into browser cache
    browser.navigate(f'{server.url(non_enrolled_dnsnames[0])}/console_log.png')
    server.wait_for({"/favicon.ico"})

    # enroll the site
    with open(f'{root}/.well-known/webcat/bundle.json') as bundle:
        enrollment = json.load(bundle)["enrollment"]
        canonical_enrollment = canonicaljson.encode_canonical_json(enrollment)
        enrollment_hash = hashlib.sha256(canonical_enrollment).hexdigest()
        update_server.set(non_enrolled_dnsnames[0], enrollment_hash)
    
    sleep(2) # wait for the rescheduled update
    server.hooks["/console_log.png"] = WEBCAT_ICON
    browser.navigate(f'{server.url(non_enrolled_dnsnames[0])}/console_log.png')
    sleep(2)
    res = browser.execute("document.body.innerText")
    assert expected in res
