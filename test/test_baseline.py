import json
import os
import shutil
import tempfile
import urllib.parse
from time import sleep

import pytest

from common import *
from helpers import Browser, Hook, Server, UpdateServer

BUNDLE_PATH = "/.well-known/webcat/bundle.json"


def sign_v2(root, bundle_generator):
    """Signs a v0.2 copy of root whose index says "Hello v2!"."""
    with tempfile.TemporaryDirectory() as tmp:
        v2_dir = os.path.join(tmp, "testapp_v2")
        shutil.copytree(root, v2_dir)
        index_path = os.path.join(v2_dir, "index.html")
        with open(index_path, "r", encoding="utf-8") as f:
            html = f.read().replace("<p>Hello!</p>", "<p>Hello v2!</p>")
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html)
        config_path = os.path.join(v2_dir, "webcat.config.json")
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        config["version"] = "0.2"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f)
        bundle_path = os.path.join(tmp, "bundle_v2.json")
        bundle_generator.sign(v2_dir, output_path=bundle_path)
        with open(bundle_path, "rb") as f, open(index_path, "rb") as g:
            return f.read(), g.read()


def baseline_keys(browser: Browser):
    browser.execute("var bkeys; state.baselines.getKeys().then(k => bkeys = k);", in_extension=True)
    sleep(0.5)
    return sorted(json.loads(browser.execute("JSON.stringify(bkeys)", in_extension=True)))


def wait_for_baselines(browser: Browser, expected, timeout=10):
    for _ in range(timeout * 2):
        keys = baseline_keys(browser)
        if keys == sorted(expected):
            return
        sleep(0.5)
    assert keys == sorted(expected)


def wait_for_text(browser: Browser, expected, timeout=15):
    """The refresh flow reloads the tab after the first response."""
    for _ in range(timeout * 2):
        text = browser.execute("document.body.textContent")
        if expected in text:
            return
        sleep(0.5)
    assert expected in text


def navigate_top(browser: Browser, url):
    """Navigates the tab itself: after a framehost page the harness's current
    target is the cross-origin frame, and Browser.navigate would move that."""
    browser.execute(
        "browser.tabs.query({active: true})"
        f".then((t) => browser.tabs.update(t[0].id, {{url: {json.dumps(url)}}}))",
        in_extension=True,
    )


def delete_page(browser: Browser, url):
    browser.execute(f"browser.history.deleteUrl({{url: {json.dumps(url)}}})", in_extension=True)


def forget_site(browser: Browser, host):
    """What Forget About This Site does to history: every page of the host."""
    browser.execute(f"""(async () => {{
        const items = await browser.history.search({{text: {json.dumps(host)}, startTime: 0, maxResults: 1000}});
        for (const item of items) {{
            if (new URL(item.url).hostname === {json.dumps(host)}) await browser.history.deleteUrl({{url: item.url}});
        }}
    }})()""", in_extension=True)


@pytest.mark.parametrize("browser", ["firefox"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks", [
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK),
], indirect=["root"])
def test_baseline_downgrade_and_history(browser: Browser, server: Server, update_server: UpdateServer, bundle_generator, addon_path, root, dnsnames, non_enrolled_dnsnames):
    """
    A site that served v0.2 is refused when it serves v0.1 again, in the
    partition that saw v0.2 only. Deleting one of the site's pages from history
    keeps the baseline; forgetting the whole site drops it in every partition,
    and v0.1 is accepted again. Forgetting an embedding site drops only the
    partition under it.
    """
    enrolled = server.url(dnsnames[0])
    embedder = server.url(non_enrolled_dnsnames[0])
    key = lambda first_party: f"{dnsnames[0]}?cookieStoreId=firefox-default,firstParty={urllib.parse.quote(first_party, safe='')}"
    top, framed = key(enrolled), key(embedder)
    v2_bundle, v2_index = sign_v2(root, bundle_generator)

    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.attach_extension_console()

    # Every navigation gets its own query so the browser cache never answers
    # v0.1 top-level on two pages, and embedded under a non-enrolled site
    with server.wait_for({"/"}):
        navigate_top(browser, f"{enrolled}/")
    wait_for_text(browser, "Hello!")
    with server.wait_for({"/"}):
        navigate_top(browser, f"{enrolled}/?second")
    with server.wait_for({"/"}):
        navigate_top(browser, f"{embedder}/framehost.html?url={enrolled}/?framed")
    assert baseline_keys(browser) == sorted([top, framed])

    # v0.2 top-level
    server.hooks["/"] = Hook(v2_index, type="text/html", headers={"x-webcat-version": "0.2"})
    server.hooks[BUNDLE_PATH] = Hook(v2_bundle, type="application/json", headers={"cache-control": "no-store"})
    with server.wait_for({"/"}):
        navigate_top(browser, f"{enrolled}/?v2")
    wait_for_text(browser, "Hello v2!")

    # Back to v0.1: refused top-level, still fine where only v0.1 was seen
    del server.hooks["/"]
    del server.hooks[BUNDLE_PATH]
    with server.wait_for({BUNDLE_PATH}):
        navigate_top(browser, f"{enrolled}/?down")
    wait_for_text(browser, "ERR_WEBCAT_BASELINE_DOWNGRADE")
    with server.wait_for({"/"}):
        navigate_top(browser, f"{embedder}/framehost.html?url={enrolled}/?framed2")
    assert "BASELINE" not in json.dumps(browser.extension_logs()[-20:])

    # One page of the site gone: the baseline stays
    delete_page(browser, f"{enrolled}/?second")
    sleep(1)
    assert baseline_keys(browser) == sorted([top, framed])
    with server.wait_for({BUNDLE_PATH}):
        navigate_top(browser, f"{enrolled}/?down2")
    wait_for_text(browser, "ERR_WEBCAT_BASELINE_DOWNGRADE")

    # The whole site forgotten: every partition of it goes, v0.1 is accepted
    forget_site(browser, dnsnames[0])
    wait_for_baselines(browser, [])
    with server.wait_for({"/"}):
        navigate_top(browser, f"{enrolled}/?accept")
    wait_for_text(browser, "Hello!")
    assert baseline_keys(browser) == [top]

    # Embedded again, then the embedding site forgotten: its partition goes
    with server.wait_for({"/"}):
        navigate_top(browser, f"{embedder}/framehost.html?url={enrolled}/?framed3")
    wait_for_baselines(browser, [top, framed])
    forget_site(browser, non_enrolled_dnsnames[0])
    wait_for_baselines(browser, [top])

    # Everything gone
    browser.execute("browser.history.deleteAll()", in_extension=True)
    wait_for_baselines(browser, [])
