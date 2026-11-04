"""
Loads every domain in the list bundled in the head zip with two production
extension zips and fails if any site differs. Not run by
`make test`:

    pytest live.py --base-addon ../dist/base.zip --addon ../dist/head.zip --headless
"""
import json
import os
import re
import time
import zipfile

import pytest
from helpers import Browser

PAGE = "JSON.stringify({ready: document.readyState, uri: document.documentURI, body: document.body?.textContent || ''})"


def verdict(browser: Browser, domain: str, settle=5):
    """'ok', 'unreachable' or the ERR_WEBCAT_* code shown on the error page."""
    browser.navigate(f"https://{domain}/")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            page = json.loads(browser.execute(PAGE))
            if page["ready"] == "complete" and page["uri"] != "about:blank":
                break
        except Exception:
            pass
        time.sleep(1)
    else:
        return "unreachable"
    # shortcut: late subresource mismatches land after load, so wait once more
    time.sleep(settle)
    page = json.loads(browser.execute(PAGE))
    if page["uri"].startswith("about:neterror"):
        return "unreachable"
    m = re.search(r"ERR_WEBCAT_\w+", page["body"])
    return m.group() if m else "ok"


def start(addon, headless, port):
    b = Browser()
    b.start(headless, port=port)
    b.install_extension(addon)
    b.attach_extension_console()
    # block_meta is only written once a list has been verified and applied
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            b.execute('var meta; browser.storage.local.get("WEBCAT:block_meta").then(r => meta = r["WEBCAT:block_meta"]);', in_extension=True)
            time.sleep(1)
            if b.execute("JSON.stringify(meta ?? null)", in_extension=True) != "null":
                return b
        except Exception:
            time.sleep(1)
    b.destroy()
    raise RuntimeError("enrollment list not applied")


@pytest.fixture(scope="module")
def browsers(request, addon_path):
    headless = request.config.getoption("--headless")
    base = start(os.path.abspath(request.config.getoption("--base-addon")), headless, 6000)
    head = start(addon_path, headless, 6001)
    yield base, head
    base.destroy()
    head.destroy()


def pytest_generate_tests(metafunc):
    if "domain" in metafunc.fixturenames:
        with zipfile.ZipFile(metafunc.config.getoption("--addon")) as z:
            leaves = json.loads(z.read("data/list.json"))["leaves"]
        metafunc.parametrize("domain", [".".join(reversed(leaf[0].removeprefix("canonical/.").split("."))) for leaf in leaves])


def test_live(browsers, domain):
    base, head = browsers
    before, after = verdict(base, domain), verdict(head, domain)
    print(f"{domain}: {before} -> {after}")
    assert before == after
