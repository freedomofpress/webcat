import pytest
from time import sleep
from helpers import Browser, Server, Blob
import logging
import json

logging.getLogger("geckordp").setLevel(logging.CRITICAL)
logging.getLogger("psutil").setLevel(logging.CRITICAL)
logging.getLogger().setLevel(logging.WARNING)

WEBCAT_ICON = Blob(
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

BAD_WASM = Blob(
    "AGFzbQEAAAABCgJgAABgAn9/AX8DAwIAAQQFAXABAQEFBgEBggKCAgcRBAFhAgABYgAAAWMAAQFk"
    "AQAKCQICAAsEAEEACw==", type="applicaiton/wasm", base64=True)

[
    LOGENTRY_ALERT,
    LOGENTRY_CSP,
    LOGENTRY_WASM_FETCH,
    LOGENTRY_WASM,
    LOGENTRY_IMPORT,
    LOGENTRY_LOAD_WORKER,
    LOGENTRY_LOAD_SHAREDWORKER,
    LOGENTRY_LOAD_WASMWORKER
] = EXPECTED_LOGS = [
    ["alert.js:",True],
    ["csp.js",True],
    ["wasm_fetch.js:",True],
    ["wasm.js:",True],
    ["import.js",True],
    ["load_worker.js:",True],
    ["load_sharedworker.js:",True],
    ["load_wasmworker.js:",True]
]

def setdiff(a: list, b: list):
    a = a.copy()
    for el in b:
        try:
            a.remove(el)
        except:
            pass
    return a

@pytest.mark.parametrize("browser", ["firefox", "tor"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected, logs, errors, rejections", [

    # Basic correct execution
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, { }, "Hello!", EXPECTED_LOGS, [], []),

    # Wrong CSP
    ("cases/testapp", {
        "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {}, "ERR_WEBCAT_CSP_MISMATCH", [], [], []),

    # Missing CSP
    ("cases/testapp", {
        # No CSP header
    }, {}, "ERR_WEBCAT_HEADERS_MISSING_CRITICAL", [], [], []),

    # Hook / with static content
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/": b"<html><body>replaced index</body></html>"}, "ERR_WEBCAT_FILE_MISMATCH", [], [], []),

    # Hook /.well-known/webcat/bundle.json
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/.well-known/webcat/bundle.json": b'{"a":"b"}'}, "ERR_WEBCAT_BUNDLE_MISSING_ENROLLMENT", [], [], []),

    # Hook /js/alert.js
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/js/alert.js": b"alert('hacked');"}, "ERR_WEBCAT_FILE_MISMATCH", [], [], []),

    # Hook /wasm/addTwo.wasm
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/wasm/addTwo.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_WASM]), [], [
        ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
    ]),

    # Hook /wasm/addThree.wasm
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/wasm/addThree.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_WASM_FETCH]), [], [
        ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
    ]),

    # Hook /wasm/reverseSub.wasm
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/wasm/reverseSub.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_LOAD_WASMWORKER]), [
        ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '/workers/wasm_worker.js']
    ], []),

], ids=[
    "basic_test",
    "wrong_csp_test",
    "missing_csp_test",
    "corrupted_index_test",
    "corrupted_manifest_test",
    "corrupted_js_test",
    "corrupted_wasm_test",
    "corrupted_wasm_fetch_test",
    "corrupted_wasm_worker_test",
], indirect=["root"])
def test_webcat(browser, server, expected, logs, errors, rejections, addon_path):
    browser.install_extension(addon_path)
    sleep(7)
    browser.navigate(server.url())
    sleep(2)
    res = browser.execute("document.body.innerText")
    assert expected in res
    res = json.loads(browser.execute("JSON.stringify(window.capture?.logs || [])"))
    for log in res: assert log in logs
    for log in logs: assert log in res
    res = json.loads(browser.execute("JSON.stringify(window.capture?.errors || [])"))
    for err in res: assert err in errors
    for err in errors: assert err in res
    res = json.loads(browser.execute("JSON.stringify(window.capture?.rejections || [])"))
    for err in res: assert err in rejections
    for err in rejections: assert err in res

@pytest.mark.parametrize("browser", ["firefox", "tor"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';",
        "cache-control": "max-age=180"
    }, {"/console_log.png": WEBCAT_ICON}, "ERR_WEBCAT_FILE_MISMATCH"),
], indirect=["root"])
def test_in_memory_cache(browser, server, expected, addon_path):
    browser.navigate(f'{server.url()}/console_log.png')
    sleep(2)
    browser.install_extension(addon_path)
    sleep(7)
    browser.navigate(f'{server.url()}/console_log.png')
    sleep(2)
    res = browser.execute("document.body.innerText")
    assert expected in res
