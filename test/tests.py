import pytest
from time import sleep
from helpers import Browser, Server, Blob
import logging

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

@pytest.mark.parametrize("browser", ["firefox", "tor"], indirect=True)
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
def test_webcat(browser, server, expected, addon_path):
    browser.install_extension(addon_path)
    sleep(7)
    browser.navigate(server.url())
    sleep(2)
    res = browser.execute("document.body.innerText")
    assert expected in res

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
