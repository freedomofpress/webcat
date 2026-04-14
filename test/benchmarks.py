import json
import pytest

from time import sleep
from helpers import Browser, Server

js_code = """
    (() => {
        let result;
        if (performance.getEntriesByType('navigation').length > 0) {
            result = performance.getEntriesByType('navigation')[0].toJSON();
        } else {
            result = performance.timing;
        }
        if (typeof WebAssembly !== 'undefined' && WebAssembly.__hooked__) {
            result["webcat_executed"] = true;
        } else {
            result["webcat_executed"] = false;
        }
        return JSON.stringify(result);
    })();
"""

@pytest.mark.parametrize("root", [("cases/testapp")], indirect=True)
@pytest.mark.parametrize("warm", [(False), (True)], ids=["cold", "warm"])
@pytest.mark.parametrize("addon_installed, enrolled", [(True, True), (True, False), (False, True)], ids=["enrolled", "not_enrolled", "no_extension"])
def test_benchmark(root, warm, addon_installed, enrolled, addon_path, request, benchmark):
    def setup():
        headers = {
            "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                                       "style-src 'self'; frame-src 'none'; worker-src 'self';"
        }
        server = Server(root=root, headers=headers)
        server.start()
        browser = Browser()
        browser.start(request.config.getoption("--headless"))
        if addon_installed:
            browser.install_extension(addon_path)
            sleep(7)
        return (), {'browser': browser, 'server': server}

    def teardown(browser, server):
        browser.destroy()
        server.stop()

    def run(_, browser, server):
        url = server.url()
        if not enrolled:
            url = url.replace("127.0.0.1", "localhost")
        browser.navigate(url)
        sleep(2)
        if warm:
            browser.navigate(url)
            sleep(2)
        result_raw = browser.execute(js_code)
        result = json.loads(result_raw)
        return result['startTime']/1000, result['loadEventEnd']/1000, result['webcat_executed']

    result = benchmark.pedantic(run, setup=setup, teardown=teardown, rounds=request.config.getoption("--iterations"))
    assert result == (addon_installed and enrolled)
