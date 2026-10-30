import os
import shutil
import tempfile
import pytest
from time import sleep, monotonic
from helpers import Browser, TorBrowser, Server, Hook, UpdateServer
import json
from pytest_check import check
import urllib.parse
from common import *

@pytest.mark.parametrize("browser, incognito", [
    pytest.param("firefox", False, id="firefox"),
    pytest.param("tbb", True, id="tbb"),
    pytest.param("tbb_safer", True, id="tbb_safer"),
    pytest.param("tbb_safest", True, id="tbb_safest"),
], indirect=["browser"])
@pytest.mark.parametrize("in_frame, first_party", [
    pytest.param(False, "https://site1.localhost:8443", id="plain"),
    pytest.param(True, "https://nonenrolled.localhost:8443", id="in_frame"),
])
@pytest.mark.parametrize("root, headers, hooks, expected, logs, errors, rejections, paths_to_wait, origin_cached", [

    # Basic correct execution
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK, "Hello!", EXPECTED_LOGS, [], [], NON_FRAME_PATHS, True,
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
                LOGENTRY_ERROR_SHAREDWORKER_ONERROR,
                LOGENTRY_ERROR_SHAREDWORKER_CALLBACK,
                LOGENTRY_ERROR_SHAREDWORKER_HANDLER,
                LOGENTRY_ERROR_WORKER_ONERROR,
                LOGENTRY_ERROR_WORKER_CALLBACK,
                LOGENTRY_ERROR_WORKER_HANDLER,
            ]), [], [],
        NON_FRAME_PATHS-WASM_PATHS-WORKER_PATHS-{"/js/wasm_frame.js"},
        True,
        id="no_wasm_test"),

    # Wrong CSP
    pytest.param("cases/testapp", {
            "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                    "style-src 'self'; frame-src 'none'; worker-src 'self';"
        }, FRAMEHOST_HOOK, "ERR_WEBCAT_CSP_MISMATCH", [], [], [], {"/"}, False,
        id="wrong_csp_test"),

    # Missing CSP
    pytest.param("cases/testapp", {
            # No CSP header
        }, FRAMEHOST_HOOK, "ERR_WEBCAT_HEADERS_MISSING_CRITICAL", [], [], [], {"/"}, False,
        id="missing_csp_test"),

    # Hook / with static content
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/": b"<html><body>replaced index</body></html>"}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/"}, True,
        id="corrupted_index_test"),

    # Hook /.well-known/webcat/bundle.json
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/.well-known/webcat/bundle.json": b'{"a":"b"}'}, "ERR_WEBCAT_BUNDLE_MISSING_ENROLLMENT", [], [], [], {"/"}, False,
        id="corrupted_manifest_test"),

    # Hook /js/alert.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/js/alert.js": b"alert('hacked');"}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/js/alert.js"}, True,
        id="corrupted_js_test"),

    # Hook /wasm/addTwo.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/addTwo.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_WASM]), [], [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
        ], NON_FRAME_PATHS, True,
        id="corrupted_wasm_test"),

    # Hook /wasm/addThree.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/addThree.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_WASM_FETCH]), [], [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
        ], NON_FRAME_PATHS, True,
        id="corrupted_wasm_fetch_test"),

    # Hook /wasm/reverseSub.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/reverseSub.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_LOAD_WASMWORKER]), [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '/workers/wasm_worker.js']
        ], [], NON_FRAME_PATHS, True,
        id="corrupted_wasm_worker_test"),

    # Hook /workers/worker.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/workers/worker.js": Hook(b"console.log('hacked');", "text/javascript")}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/workers/worker.js"}, True,
        id="corrupted_worker_test"),

    # Hook /workers/sharedworker.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/workers/sharedworker.js": Hook(b"console.log('hacked');", "text/javascript")}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/workers/sharedworker.js"}, True,
        id="corrupted_sharedworker_test"),

    # Hook /workers/serviceworker.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/workers/serviceworker.js": Hook(b"console.log('hacked');", "text/javascript")}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/workers/serviceworker.js"}, True,
        id="corrupted_serviceworker_test"),

    # Hook /workers/audioworklet.js
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/workers/audioworklet.js": Hook(b"console.log('hacked');", "text/javascript")}, "ERR_WEBCAT_FILE_MISMATCH", [], [], [], {"/workers/audioworklet.js"}, True,
        id="corrupted_audioworklet_test"),
    
    # Hook /wasm/aw_addTwo.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/aw_addTwo.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_LOAD_AUDIOWORKLET]), [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '/workers/audioworklet.js']
        ], [], NON_FRAME_PATHS, True,
        id="corrupted_wasm_audioworklet_test"),

    # Hook /wasm/inline_addTwo.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/inline_addTwo.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_INLINE]), [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
        ], [], NON_FRAME_PATHS, True,
        id="corrupted_wasm_inline_test"),

    # Hook /wasm/frame_addThree.wasm
    pytest.param("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {"/wasm/frame_addThree.wasm": BAD_WASM}, "Hello!", setdiff(EXPECTED_LOGS, [LOGENTRY_WASM_FRAME]), [], [
            ['Error: [WEBCAT] Unauthorized WebAssembly bytecode: HBppdg6328KAR4wUuqq0tuD4b7l5Wrl9ne6AfB4C0G4', '']
        ], NON_FRAME_PATHS, True,
        id="corrupted_wasm_frame_test"),

], indirect=["root"])
def test_webcat(browser, in_frame, server: Server, update_server: UpdateServer, expected, logs, errors, rejections,
                paths_to_wait, origin_cached, first_party, incognito, addon_path, dnsnames, non_enrolled_dnsnames):
    """
    Tests the basic verification and blocking behavior, both in the top-level
    frame and in an iframe. Performs five distinct checks:

     - Do page contents match expectations?
     - Does console.log output match expectation?
     - Do uncaught errors match expectations?
     - Do uncaught Promise rejections match expectations?
     - Do the generated origin cache entries match expectations?
    """
    logs, errors, rejections = logs.copy(), errors.copy(), rejections.copy()
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.attach_extension_console()
    if isinstance(browser, TorBrowser) or in_frame:
        # ServiceWorkers are disabled in TBB by NoScript and in frames by WEBCAT
        paths_to_wait = paths_to_wait-SERVICEWORKER_PATHS
    if in_frame:
        url = f"{server.url(non_enrolled_dnsnames[0])}/framehost.html?url={server.url(dnsnames[0])}"
    else:
        url = server.url(dnsnames[0])
    with server.wait_for(paths_to_wait):
        browser.navigate(url)
    if not in_frame:
        res = browser.execute("document.body.textContent")
        if "__WEBCAT_" in res:
            raise Fatal(f"Marker leaked to response content: {res}")
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

    browser.execute("var keys; state.origins.keys().then(k => keys = k);", in_extension=True)
    cache_keys = json.loads(browser.execute("JSON.stringify(keys)", in_extension=True))
    if origin_cached:
        assert [f"{dnsnames[0]}?firstParty={urllib.parse.quote(first_party, safe="")},incognito={"true" if incognito else "false"}"] == cache_keys
    else:
        assert [] == cache_keys

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
    """
    Tests that concurrent errors in separate tabs don't conflict with each
    other: a corrupted script should be treated as such despite a simultaneous
    verification error in another tab.
    """
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    with server.wait_for({"/js/alert.js"}):
        browser.execute(
            f"window.open('{server.url()}');"
            f"setTimeout(() => location.href = '{server.url()}/x', 1000)"
        )
    res = browser.execute("document.body.textContent")
    assert expected in res

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer", "tbb_safest"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks, expected", [
    pytest.param("cases/testapp", EXPECTED_CSP, {
            "/js/alert.js": Hook(b"alert('hacked');", type="text/javascript"),
        }, "ERR_WEBCAT_FILE_MISMATCH",
        id="non_enrolled_loads_enrolled_subresource_test"),
], indirect=["root"])
def test_non_enrolled_subresource(browser: Browser, server: Server, update_server: UpdateServer, expected, addon_path, dnsnames, non_enrolled_dnsnames):
    """
    Tests that a subresource from an enrolled origin on a non-enrolled page is
    verified correctly: when the enrolled subresource is corrupted, the
    non-enrolled page should be blocked.
    """
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
    with server.wait_for({"/js/alert.js"}):
        browser.navigate(non_enrolled_url)
    res = browser.execute("document.body.textContent")
    assert expected in res

@pytest.mark.parametrize("browser, paths_to_wait", [
    pytest.param("firefox", NON_FRAME_PATHS, id="firefox"),
    pytest.param("tbb", NON_FRAME_PATHS-SERVICEWORKER_PATHS, id="tbb"),
    pytest.param("tbb_safer", NON_FRAME_PATHS-SERVICEWORKER_PATHS-WASM_PATHS, id="tbb_safer"),
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
    """
    Tests that verification can be delegated to a different origin's
    enrollment. Delegating to a non-enrolled origin is not allowed.
    """
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    # Subscribe before navigation so we don't miss the "Setting ok icon" line
    browser.attach_extension_console()
    with server.wait_for(paths_to_wait):
        browser.navigate(f"{server.url(dnsnames[0])}/")

    # Page loads successfully in both cases
    assert "Hello!" in browser.execute("document.body.textContent")

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
    pytest.param("tbb", NON_FRAME_PATHS-SERVICEWORKER_PATHS, id="tbb"),
    pytest.param("tbb_safer", NON_FRAME_PATHS-SERVICEWORKER_PATHS-WASM_PATHS, id="tbb_safer"),
    pytest.param("tbb_safest", NON_FRAME_PATHS-JS_PATHS-WORKER_PATHS-WASM_PATHS, id="tbb_safest")
], indirect=["browser"])
@pytest.mark.parametrize("root, headers, hooks, expected", [
    pytest.param("cases/testapp", EXPECTED_CSP, {}, "Hello v2!",
        id="version_refresh_test"),
], indirect=["root"])
def test_version_refresh(browser: Browser, server: Server, update_server: UpdateServer, bundle_generator, expected, paths_to_wait, addon_path, root):
    """
    Tests that a server can update its manifest during an active session.
    Updated resources should be rendered in the browser with no errors.
    """
    # Load v0.1: server serves the bundle that the `root` fixture signed.
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    with server.wait_for(paths_to_wait):
        browser.navigate(server.url())
    assert "Hello!" in browser.execute("document.body.textContent")

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

    with server.wait_for(paths_to_wait):
        browser.execute("location.reload()")
    assert expected in browser.execute("document.body.textContent")

@pytest.mark.parametrize("browser", ["firefox"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks", [
    ("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {}),
], indirect=["root"])
def test_bundle_redirect(browser: Browser, server: Server, update_server: UpdateServer, addon_path, root, dnsnames, non_enrolled_dnsnames):
    """
    Tests that the extension blocks HTTP redirects on bundle fetch. The tab
    associated with the fetch should display an error when the bundle URL
    redirects across origins.
    """
    bundle_path = "/.well-known/webcat/bundle.json"
    target = "/redirect-target-bundle.json"
    with open(f"{root}{bundle_path}", "rb") as f:
        bundle = f.read()
    server.hooks[target] = Hook(bundle, type="application/json")
    browser.install_extension(addon_path)
    update_server.wait_for_update()

    # A cross-origin redirect of the bundle fetch must be cancelled before it
    # is followed: validation fails and the target is never requested
    server.hooks[bundle_path] = Hook(b"", status=302, headers={
        "Location": f"{server.url(non_enrolled_dnsnames[0])}{target}"})
    served = Server._counts.get(target, 0)
    with server.wait_for({"/", bundle_path}):
        browser.navigate(server.url(dnsnames[0]))
    res = browser.execute("document.body.textContent")
    assert "ERR_WEBCAT_BUNDLE_FETCH_ERROR" in res
    assert Server._counts.get(target, 0) == served, "cross-origin redirect target was fetched"

    # A same-origin redirect is followed and the bundle validates normally
    server.hooks[bundle_path] = Hook(b"", status=302, headers={
        "Location": f"{server.url(dnsnames[1])}{target}"})
    with server.wait_for(NON_FRAME_PATHS):
        browser.navigate(server.url(dnsnames[1]))
    assert "Hello!" in browser.execute("document.body.textContent")

@pytest.mark.parametrize("browser", ["firefox"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks", [
    ("cases/testapp", EXPECTED_CSP, FRAMEHOST_HOOK | {}),
], indirect=["root"])
def test_default_fallback(browser: Browser, server: Server, update_server: UpdateServer, addon_path, root, dnsnames):
    """
    Tests fallback hash behavior. Top-level navigations to paths not present in
    the manifest are allowed if the contents match a fallback; loading
    subresources from paths missing from the manifest is not and should trigger
    an error.
    """
    # Serve the fallback content for paths missing from the manifest, as a
    # server attempting to swap resources would
    index = open(f"{root}/index.html", "rb").read()
    server.hooks["/stale-page"] = Hook(index, type="text/html")
    server.hooks["/stale-dir/"] = Hook(index, type="text/html")
    server.hooks["/js/not-in-manifest.js"] = Hook(index, type="text/javascript")
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.attach_extension_console()

    # A main_frame navigation to a path missing from the manifest falls back
    # to default_fallback and verifies
    with server.wait_for({"/stale-page"}):
        browser.navigate(f"{server.url(dnsnames[0])}/stale-page")
    assert "Hello!" in browser.execute("document.body.textContent")

    # A subresource missing from the manifest must fail, even if its content
    # matches default_fallback
    with server.wait_for({"/js/not-in-manifest.js"}):
        browser.execute(
            "var s = document.createElement('script');"
            "s.src = '/js/not-in-manifest.js';"
            "document.head.appendChild(s);"
        )
    assert "ERR_WEBCAT_FILE_MISSING" in browser.execute("document.body.textContent")

    # A directory path whose default_index entry is missing also falls back on
    # main_frame navigations (#229). Only the frame itself is asserted: the
    # fallback page's relative subresources legitimately fail per #195
    with server.wait_for({"/stale-dir/"}):
        browser.navigate(f"{server.url(dnsnames[0])}/stale-dir/")
    assert "/stale-dir/ verified." in json.dumps(browser.extension_logs())

OAC_HOOKS = {
    # Enrolled page embedding a frame; needs frame-src, so its CSP is pinned per path in webcat.config.json
    "/oac/parent.html": Hook(open("cases/testapp/oac/parent.html", "rb").read(), type="text/html", headers={
        "content-security-policy": json.load(open("cases/testapp/webcat.config.json"))["extra_csp"]["/oac/parent.html"],
    }),
    # Same-site, non-enrolled frame: tries to merge origins via document.domain and to hand over a compiled module
    "/oac/frame.html": Hook(b"""<!DOCTYPE html><script>
const results = {};
const module = new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
try {
    document.domain = location.hostname.replace(/^[^.]+\\./, "");
    parent.oac.moduleHandedOver = module; // direct hand-over, only works once origins are merged
    results.parentAccess = "ok";
} catch (e) { results.parentAccess = e.name; }
parent.postMessage({ module }, "*");
parent.postMessage({ results }, "*");
</script>""", type="text/html", headers={"content-security-policy": ""}),
}

@pytest.mark.parametrize("browser", ["firefox"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks", [
    ("cases/testapp", EXPECTED_CSP, OAC_HOOKS),
], indirect=["root"])
@pytest.mark.parametrize("parent, isolated, historical_cluster", [
    # The extension origin-keys the enrolled parent, so the same-site frame behaves like a cross-site one
    pytest.param("site1.localhost", True, False, id="enrolled_parent"),
    # When a historical agent cluster prevents origin-keying, the extension blocks
    pytest.param("site1.localhost", True, True, id="historical_cluster"),
    # Control: stock Firefox lets a same-site frame merge origins, so the case above isn't vacuous
    pytest.param("nonenrolled.localhost", False, False, id="non_enrolled_parent"),
])
def test_same_site_frame_isolation(browser: Browser, server: Server, update_server: UpdateServer, addon_path, parent, isolated, historical_cluster):
    """
    Tests that Origin Agent Clustering (OAC) is enforced correctly: A framed
    subdomain should not be able to access its parent even if both frames opt
    in to domain relaxing. When OAC is unavailable due to a historical agent
    cluster, the frame should be blocked with an error.
    """
    frame_url = f"{server.url(f'frame.{parent}')}/oac/frame.html"
    if historical_cluster:
        with server.wait_for({"/oac/parent.html", "/oac/frame.html"}):
            browser.navigate(f"{server.url(parent)}/oac/parent.html?frame={urllib.parse.quote(frame_url, safe='')}")
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    with server.wait_for({"/oac/parent.html", "/oac/frame.html"} if not historical_cluster else {"/oac/parent.html"}):
        browser.navigate(f"{server.url(parent)}/oac/parent.html?frame={urllib.parse.quote(frame_url, safe='')}")
    if historical_cluster:
        res = browser.execute("document.body.textContent")
        assert "ERR_WEBCAT_FRAME_ISOLATION_OAC_UNAVAILABLE" in res
        return
    deadline = monotonic() + 10
    dump = 'JSON.stringify(window.oac, (k, v) => k.startsWith("module") ? String(v) : v)'
    while "parentAccess" not in (oac := json.loads(browser.execute(dump))):
        assert monotonic() < deadline, f"frame did not report within 10s: {oac}"
        sleep(0.2)
    module = "[object WebAssembly.Module]"
    assert oac == ({
        "originAgentCluster": True,
        "parentAccess": "SecurityError",
        "messageError": True,  # the posted module is rejected by the receiver
    } if isolated else {
        "originAgentCluster": False,
        "parentAccess": "ok",
        "moduleReceived": module,
        "moduleHandedOver": module,
    })


@pytest.mark.parametrize("browser", ["firefox"], indirect=True)
@pytest.mark.parametrize("root, headers, hooks", [
    ("cases/testapp", EXPECTED_CSP, {}),
], indirect=["root"])
def test_config_paths(browser: Browser, update_server: UpdateServer, addon_path):
    """
    Tests that the configured paths of the extension all resolve. Bundled data,
    the static hook script, the error page, and icons must all be present, even
    a custom extension built using the library, where the assets have been
    relocated.
    """
    browser.install_extension(addon_path)
    update_server.wait_for_update()
    browser.attach_extension_console()
    browser.execute(
        "var results; (async () => {"
        "  const c = state.config;"
        "  const paths = [`${c.localDataPath}/list.json`, `${c.localDataPath}/block.json`, c.staticHookPath,"
        "    c.pagePaths({name: 'error'}),"
        "    ...['webcat', 'webcat-ok', 'webcat-error'].map(name => c.iconPaths({name}))];"
        "  results = await Promise.all(paths.map(async p =>"
        "    [p, await fetch(browser.runtime.getURL(p)).then(r => r.ok, () => false)]));"
        "})();",
        in_extension=True)
    deadline = monotonic() + 10
    while not isinstance(results := browser.execute("JSON.stringify(results)", in_extension=True), str):
        assert monotonic() < deadline, "config paths not resolved within 10s"
        sleep(0.2)
    results = json.loads(results)
    assert [p for p, ok in results if not ok] == []
