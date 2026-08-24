import json
import pytest

from time import sleep
from helpers import Browser, Server
from tests import EXPECTED_CSP

js_code = """
    (() => {
        let result;
        if (performance.getEntriesByType('navigation').length > 0) {
            result = performance.getEntriesByType('navigation')[0].toJSON();
        } else {
            result = performance.timing;
        }
        try {
            new WebAssembly.Module(new ArrayBuffer());
        } catch (err) {
            result["webcat_executed"] = err.message.includes("WEBCAT");
        }
        return JSON.stringify(result);
    })();
"""

@pytest.mark.parametrize("root", [("cases/testapp")], indirect=True)
@pytest.mark.parametrize("warm", [(False), (True)], ids=["cold", "warm"])
@pytest.mark.parametrize("addon_installed, enrolled", [(True, True), (True, False), (False, True)], ids=["enrolled", "not_enrolled", "no_extension"])
def test_benchmark(root, update_server, warm, addon_installed, enrolled, addon_path, request, benchmark, ssl_cert, non_enrolled_dnsnames):
    def setup():
        cert_path, key_path = ssl_cert
        server = Server(
            root=root,
            headers=EXPECTED_CSP,
            ssl_cert=cert_path,
            ssl_key=key_path,
        )
        server.start()
        browser = Browser()
        browser.trust_cert(cert_path, server.port, non_enrolled_dnsnames)
        browser.start(request.config.getoption("--headless"))
        if addon_installed:
            since = update_server.update_count()
            browser.install_extension(addon_path)
            update_server.wait_for_update(since)
        return (), {'browser': browser, 'server': server}

    def teardown(browser, server):
        browser.destroy()
        server.stop()

    def run(_, browser, server):
        url = server.url()
        if not enrolled:
            url = server.url(non_enrolled_dnsnames[0])
        browser.navigate(url)
        sleep(2)
        if warm:
            browser.navigate(url)
            sleep(2)
        result_raw = browser.execute(js_code)
        result = json.loads(result_raw)
        return result['startTime']/1000, result['loadEventEnd']/1000, result['webcat_executed']

    benchmark.group = "warm" if warm else "cold"
    result = benchmark.pedantic(run, setup=setup, teardown=teardown, rounds=request.config.getoption("--iterations"))
    assert result == (addon_installed and enrolled)
