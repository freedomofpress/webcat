import pytest
from time import sleep
from helpers import Browser, Server
import logging
import pytest

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


@pytest.mark.parametrize("headers, hooks, expected", [
    # Basic correct execution
    ({
        "x-sigstore-signers": '[{"identity": "giulio@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "x-sigstore-threshold": "2",
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {}, "Hello!"),

    # Full stripping
    ({
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {}, "Something went wrong. The request was blocked."),

    # Wrong threshold
    ({
        "x-sigstore-signers": '[{"identity": "giulio@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "x-sigstore-threshold": "1",
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {}, "Something went wrong. The request was blocked."),

    # Wrong signers
    ({
        "x-sigstore-signers": '[{"identity": "giulio@test.com", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "x-sigstore-threshold": "2",
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {}, "Something went wrong. The request was blocked."),

    # Wrong CSP
    ({
        "x-sigstore-signers": '[{"identity": "giulio@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "x-sigstore-threshold": "2",
        "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {}, "Something went wrong. The request was blocked."),

    # Missing threshold
    ({
        "x-sigstore-signers": '[{"identity": "giulio@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {}, "Something went wrong. The request was blocked."),

    # Missing signers
    ({
        "x-sigstore-threshold": "2",
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/hello": b"Hi from test!"}, "Something went wrong. The request was blocked."),

    # Missing CSP
    ({
        "x-sigstore-signers": '[{"identity": "giulio@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "x-sigstore-threshold": "2"
        # No CSP header
    }, {}, "Something went wrong. The request was blocked."),

    # Hook / with static content
    ({
        "x-sigstore-signers": '[{"identity": "giulio@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "x-sigstore-threshold": "2",
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/": b"<html><body>replaced index</body></html>"}, "Something went wrong. The request was blocked."),
    # Hook /webcat.json
    ({
        "x-sigstore-signers": '[{"identity": "giulio@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "x-sigstore-threshold": "2",
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/webcat.json": b'{"a":"b"}'}, "Something went wrong. The request was blocked."),
    # Hook /js/alert.js
    ({
        "x-sigstore-signers": '[{"identity": "giulio@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, '
                              '{"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "x-sigstore-threshold": "2",
        "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                   "style-src 'self'; frame-src 'none'; worker-src 'self';"
    }, {"/js/alert.js": b"alert('hacked');"}, "Something went wrong. The request was blocked."),

], ids=[
    "basic_test",
    "stripping_test",
    "wrong_threshold_test",
    "wrong_signers_test",
    "wrong_csp_test",
    "missing_threshold_test",
    "missing_signers_test",
    "missing_csp_test",
    "corrupted_index_test",
    "corrupted_manifest_test",
    "corrupted_js_test"
])
def test_webcat(headers, hooks, expected, addon_path):
    srv, browser = setup_browser_and_server(
        root="cases/testapp",
        headers=headers,
        hooks=hooks,
        extension_path=addon_path
    )
    try:
        res = browser.execute("document.body.innerText")
        assert res == expected
    finally:
        teardown_browser_and_server(srv, browser)
