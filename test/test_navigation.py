import json
import pytest
from urllib.parse import quote
from time import sleep
from helpers import Browser, Server, UpdateServer, Hook
from common import *

# An embedder whose first bytes frame the enrolled origin: the frame exists as
# early as a frame can
EMBEDDER = b'<!DOCTYPE html><iframe src="https://site1.localhost:8443/race/quiet.html"></iframe>'
ROUNDS = 6

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks", [
    pytest.param("cases/testapp", EXPECTED_CSP, {
        "/embedder.html": Hook(EMBEDDER, type="text/html", headers={"content-security-policy": "", "cache-control": "max-age=600"}),
        "/plain.html": Hook(b"<!DOCTYPE html><p>plain</p>", type="text/html", headers={"content-security-policy": ""}),
    }, id="navigation_race"),
], indirect=["root"])
@pytest.mark.parametrize("embeds_owner", [True, False], ids=["embeds_owner", "no_owner"])
def test_navigation_race(browser: Browser, server: Server, update_server: UpdateServer, addon_path, dnsnames, non_enrolled_dnsnames, embeds_owner):
    """
    A worker of the page being left keeps issuing requests while the tab
    navigates away. Each of them keeps the outgoing site as first party or is
    cancelled, even when the incoming site frames the worker's origin from its
    first bytes with the frame's document already cached and verified.
    """
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.attach_extension_console()
    site1 = server.url(dnsnames[0])
    ne = server.url(non_enrolled_dnsnames[0])
    b_url = f"{ne}/embedder.html" if embeds_owner else f"{ne}/plain.html"
    stragglers = 0
    for _ in range(ROUNDS):
        if embeds_owner:
            # Warm the frame's document and its partition state
            browser.navigate(b_url)
            sleep(1.0)
        browser.navigate(f"{site1}/race/")
        sleep(1.0)
        n0 = len(browser.extension_logs())
        browser.navigate(b_url)
        sleep(1.5)
        for entry in browser.extension_logs()[n0:]:
            line = json.dumps(entry)
            if "/race/ping.js?" not in line:
                continue
            if "Attributed" in line:
                assert f"to {site1}" in line, f"request of the outgoing page's worker attributed elsewhere: {line[:300]}"
            if "Unattributable" in line:
                stragglers += 1
    browser.execute("var keys; state.origins.keys().then(k => keys = k);", in_extension=True)
    cache_keys = json.loads(browser.execute("JSON.stringify(keys)", in_extension=True))
    # Only the partitions a genuine visit creates: site1 top-level, and site1
    # under the embedder when it frames it
    first_parties = sorted(k.split("firstParty=")[1].split(",")[0] for k in cache_keys)
    expected = sorted({quote(site1, safe="")} | ({quote(ne, safe="")} if embeds_owner else set()))
    assert first_parties == expected
    print(f"\nstragglers cancelled over {ROUNDS} navigations: {stragglers}")

# A framed enrolled document's worker keeps issuing requests while the tab
# navigates to the enrolled origin. Firefox ESR reports worker loads under
# frame 0 (https://bugzilla.mozilla.org/show_bug.cgi?id=2048884), so a load
# arriving after the frame is gone would pass the frame check against the new
# top-level document; the worker registry resolves it from the script's own
# attribution. See the race examples in extension/src/webcat/firstparty.ts.
@pytest.mark.parametrize("browser", ["firefox", "tbb"], indirect=True)
@pytest.mark.parametrize("mode", ["fetch", "import", "nested"])
@pytest.mark.parametrize("root, headers, hooks", [
    pytest.param("cases/testapp", EXPECTED_CSP, {
        f"/{page}.html": Hook(b'<!DOCTYPE html><iframe src="https://site1.localhost:8443/race/' + page.encode() + b'.html"></iframe>', type="text/html", headers={"content-security-policy": ""})
        for page in ("index", "import", "nested")
    }, id="race_to_owner"),
], indirect=["root"])
def test_navigation_race_to_owner(browser: Browser, server: Server, update_server: UpdateServer, addon_path, dnsnames, non_enrolled_dnsnames, mode):
    """
    The embedder frames an enrolled page whose worker fetches, imports or
    spawns workers in a loop; the tab then navigates to the enrolled origin.
    Every request of the frame's worker keeps the embedder as first party or
    is cancelled.
    """
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.attach_extension_console()
    site1 = server.url(dnsnames[0])
    ne = server.url(non_enrolled_dnsnames[0])
    page = "index" if mode == "fetch" else mode
    wrong = []
    for _ in range(ROUNDS):
        browser.navigate(f"{ne}/{page}.html")
        sleep(1.0)
        n0 = len(browser.extension_logs())
        browser.navigate(f"{site1}/race/quiet.html")
        sleep(1.5)
        for entry in browser.extension_logs()[n0:]:
            line = json.dumps(entry)
            if "/race/ping.js?" in line and "Attributed" in line and f"to {ne}" not in line:
                wrong.append(line[:300])
    assert wrong == [], "request of the frame's worker attributed to the new top-level site"
