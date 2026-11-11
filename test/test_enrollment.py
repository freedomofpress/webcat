import json
import pytest
import urllib.parse
from time import sleep, monotonic
from helpers import Browser, TorBrowser, Server, UpdateServer, Hook
from common import *

# Set on a document loaded without WEBCAT; a reload wipes it
MARKER = "window.__webcat_unverified = true"
EMBEDDER = Hook(b'<!DOCTYPE html><iframe src="https://site1.localhost:8443/race/"></iframe>', type="text/html", headers={"content-security-policy": ""})

def wait_for_reload(browser: Browser, timeout=15):
    deadline = monotonic() + timeout
    while browser.execute("typeof window.__webcat_unverified") != "undefined":
        assert monotonic() < deadline, "the tab was not reloaded"
        sleep(0.5)

def origin_keys(browser: Browser):
    browser.execute("var keys; state.origins.keys().then(k => keys = k);", in_extension=True)
    return json.loads(browser.execute("JSON.stringify(keys)", in_extension=True))

def origin_key(browser: Browser, fqdn: str, first_party: str):
    store = "firefox-private" if isinstance(browser, TorBrowser) else "firefox-default"
    return f"{fqdn}?cookieStoreId={store},firstParty={urllib.parse.quote(first_party, safe='')}"

@pytest.mark.parametrize("browser", ["firefox", "tbb"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks", [
    pytest.param("cases/testapp", EXPECTED_CSP, {"/embedder.html": EMBEDDER}, id="reload_on_install"),
], indirect=["root"])
@pytest.mark.parametrize("page", ["workers", "pinger", "framed_pinger"])
def test_reload_on_install(browser: Browser, server: Server, update_server: UpdateServer, addon_path, dnsnames, non_enrolled_dnsnames, page):
    """
    A document of an enrolled host open before WEBCAT was installed is
    reloaded through WEBCAT once the first list lands (#273, scenario 1):
    the enrolled site at the top level with every kind of worker running, a
    page whose worker keeps requests in flight through the reload, and that
    page framed by a non-enrolled site.
    """
    site1 = server.url(dnsnames[0])
    ne = server.url(non_enrolled_dnsnames[0])
    first_party = site1
    if page == "workers":
        url, paths = site1, NON_FRAME_PATHS-SERVICEWORKER_PATHS if isinstance(browser, TorBrowser) else NON_FRAME_PATHS
    elif page == "pinger":
        url, paths = f"{site1}/race/", {"/race/start.js"}
    else:
        url, paths, first_party = f"{ne}/embedder.html", {"/race/start.js"}, ne
    with server.wait_for(paths):
        browser.navigate(url)
    # Loaded without WEBCAT, the origin is site-keyed in this browsing context
    # group, which is why a plain reload could not pass the OAC check
    assert not browser.execute("window.originAgentCluster")
    browser.execute(MARKER)

    # Fetches of the new tab may come from the HTTP cache, so wait on the
    # marker rather than on the server
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    wait_for_reload(browser)
    browser.attach_extension_console()
    assert origin_keys(browser) == [origin_key(browser, dnsnames[0], first_party)]

@pytest.mark.parametrize("browser", ["firefox", "tbb"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks", [
    pytest.param("cases/testapp", EXPECTED_CSP, {}, id="reload_on_enrollment"),
], indirect=["root"])
def test_reload_on_enrollment(browser: Browser, server: Server, update_server: UpdateServer, addon_path, dnsnames, non_enrolled_dnsnames):
    """
    A document of a host that gets enrolled while it is open is reloaded
    through WEBCAT when the list enrolling it lands (#273, scenario 2).
    """
    ne = server.url(non_enrolled_dnsnames[0])
    # The first network update schedules a second one; the host must be
    # enrolled before it fires
    update_server.reschedule(5, once=True)
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    with server.wait_for({"/race/start.js"}):
        browser.navigate(f"{ne}/race/")
    browser.execute(MARKER)

    since = update_server.update_count()
    update_server.set(non_enrolled_dnsnames[0], update_server._hosts[dnsnames[0]])
    update_server.wait_for_update(since)
    wait_for_reload(browser)
    browser.attach_extension_console()
    assert origin_keys(browser) == [origin_key(browser, non_enrolled_dnsnames[0], ne)]
