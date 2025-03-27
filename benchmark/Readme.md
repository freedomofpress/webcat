# Benchmarking tools
## bench.py
The purpose of this test suite is to automate performance benchmarks to measure the overhead and performance impact of having the WEBCAT browser extension installed. The test suite expects two URLs, one enrolled and one non-enrolled. For the test to be accurate, the two URLs should point to the same server and app, so that on the average what is measured is only the overhead of the extension. The extension zipfile to pass to the command line of this tool can be built by running `make package` in the `extension/` folder.

For instance, most tests have been performed using:
 * `https://webcat.nym.re` as an enrolled URL
 * `https://webcat-element.pages.dev` a non enrolled URL

They both point to the same Cloudflare Pages instance. They are a good test to see real-world performance, including network fluctuations, while more accurate testing could be performed by hosting locally instead. A browser state is very complex, and performances degrades over time. As such, warm tests are collected by visiting a second time the test url after a cold test, then the browser is killed and the profile is removed. When testing with a long lived browser instance, warm baseline performance degrades, becoming slower than cold tests.

Tests can be performed in two different scenarios:
 * _Cold_: fresh browser profile and session, caches empty
 * _Warm_: the URL has been previously visited, both the browser cache and the WEBCAT cache are populated

_Cold_ tests are particularly slow: a new profile for Firefox is created, then the browser is started, the extension is installed and there is a wait time for the extension to initialize (download and import the trust chain and the preload list).

The script runs six tests by default, and saves the output to a Sqlite database, `results.db`.

The tests are:

| Scenario | Enrolled | Extension |
|-|-|-|
| Cold | Yes | Yes |
| Cold | No | Yes |
| Cold | N/A | No |
| Warm | Yes | Yes |
| Warm | No | Yes |
| Warm | N/A | No |

The purpose of extra test without the browser extension is to get the baseline performance to compare with.

Performance data are gathered by calling [performance.getEntriesByType()](https://developer.mozilla.org/en-US/docs/Web/API/Performance/getEntriesByType). Furthermore, in the _enrolled_ case, the script checks for the [WebAssembly hooks marker](https://github.com/freedomofpress/webcat/blob/56e8906b089e730a9412482cd5878a905f1fc0cc/extension/src/webcat/hooks.ts#L7) to confirm that WEBCAT has indeed been executed. If that is not the case, the result is discarded and the iteration is repeated.

The tool uses [geckordp](https://github.com/jpramosi/geckordp), a library to use the Firefox Remote Debugging Protocol, and as such it is Firefox specific. Contrary to Chromium based browsers, Firefox does not support taking an extension path from the command line. Selenium and other automation tools either use the CDP API or Marionette, and as far as I could test, neither supported installing temporary addons. Thus, this method could be in the future the most convenient to implement functional tests.

### Install
Firefox needs to be already installed.

```bash
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
```

### Usage
```bash
usage: bench.py [-h] --addon ADDON --iterations ITERATIONS --enrolled-url ENROLLED_URL --non-enrolled-url NON_ENROLLED_URL [--headless HEADLESS]

Performance tester for WEBCAT extension.

options:
  -h, --help            show this help message and exit
  --addon ADDON         Path to the temporary addon
  --iterations ITERATIONS
                        Number of iterations per test
  --enrolled-url ENROLLED_URL
                        URL for the enrolled domain
  --non-enrolled-url NON_ENROLLED_URL
                        URL for the non-enrolled domain
  --headless HEADLESS   Headless mode
```
 The script saves each iteration, and if run multiple times it will resume from the last run.