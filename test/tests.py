import pytest
from time import sleep
from helpers import Browser, Server, Blob
import logging

logging.getLogger("geckordp").setLevel(logging.CRITICAL)
logging.getLogger("psutil").setLevel(logging.CRITICAL)
logging.getLogger().setLevel(logging.WARNING)

def setup_browser_and_server(root, headers=None, hooks=None, extension_path=None, headless=False):
    srv = Server(
        root=root,
        headers=headers or {},
        hooks=hooks or {}
    )
    browser = Browser(headless=headless)
    if extension_path:
        browser.install_extension(extension_path)
        sleep(7)

    srv.start()
    sleep(1)
    browser.navigate(srv.url())
    sleep(2)
    return srv, browser

def teardown_browser_and_server(srv, browser):
    srv.stop()
    browser.destroy()

@pytest.mark.parametrize("root, headers, hooks, expected", [
    # Basic correct execution
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {}, "Hello!"),

    # Wrong CSP
    ("cases/testapp", {
        "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {}, "ERR_WEBCAT_CSP_MISMATCH"),

    # Missing CSP
    ("cases/testapp", {
        # No CSP header
    }, {}, "ERR_WEBCAT_HEADERS_MISSING_CRITICAL"),

    # Hook / with static content
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/": b"<html><body>replaced index</body></html>"}, "ERR_WEBCAT_FILE_MISMATCH"),
    # Hook /.well-known/webcat/bundle.json
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/.well-known/webcat/bundle.json": b'{"a":"b"}'}, "ERR_WEBCAT_BUNDLE_MISSING_ENROLLMENT"),
    # Hook /js/alert.js
    ("cases/testapp", {
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/js/alert.js": b"alert('hacked');"}, "ERR_WEBCAT_FILE_MISMATCH"),

], ids=[
    "basic_test",
    "wrong_csp_test",
    "missing_csp_test",
    "corrupted_index_test",
    "corrupted_manifest_test",
    "corrupted_js_test"
], indirect=["root"])
def test_webcat(root, headers, hooks, expected, addon_path):
    srv, browser = setup_browser_and_server(
        root=root,
        headers=headers,
        hooks=hooks,
        extension_path=addon_path
    )
    try:
        res = browser.execute("document.body.innerText")
        assert expected in res
    finally:
        teardown_browser_and_server(srv, browser)

@pytest.mark.parametrize("root", [("cases/testapp")], indirect=["root"])
def test_in_memory_cache(root, addon_path):
    srv, browser = setup_browser_and_server(
        root=root,
        headers={
            "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                       "style-src 'self'; frame-src 'none'; worker-src 'self';",
            "cache-control": "max-age=180"
        },
        hooks={"/console_log.png": Blob(
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
            type="image/png", base64=True)}
    )
    browser.navigate(f'{srv.url()}/console_log.png')
    sleep(2)
    browser.install_extension(addon_path)
    sleep(7)
    browser.navigate(f'{srv.url()}/console_log.png')
    sleep(2)
    try:
        res = browser.execute("document.body.innerText")
        assert "ERR_WEBCAT_FILE_MISMATCH" in res
    finally:
        teardown_browser_and_server(srv, browser)
