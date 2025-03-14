# Benchmarking tools
## bench.py
The purpose of this test suite is to automate performance benchmarks to measure the overhead and performance impact of having the WEBCAT browser extension installed. The test suite expcts two URLs, one enrolled and one non-enrolled. For the test to be accurate, the two URLs should point to the same server and app, so that on the average what is measured is only the overhead of the extension. The extension zipfile to pass to the command line of this tool can be build by running `make package` in the `extension/` folder.

For instance, most tests have been performed using:
 * `https://webcat.nym.re` as an enrolled URL
 * `https://webcat-element.pages.dev` a non enrolled URL

They both point to the same Cloudflare Pages instance. They are a good test to demo real-lice performance, including network fluctuations, while more accurate testing could be performed by hosting everything locally.

Tests can be performed in two different scenarios:
 * _Cold_: fresh browser profile and session, caches empty
 * _Warm_: the URL has been previously visited, both the browser cache and the WEBCAT cache are populated

It also run an extra test without the browser extension to get the baseline performance to compare with.

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

Performance data are gathered by calling [performance.getEntriesByType()](https://developer.mozilla.org/en-US/docs/Web/API/Performance/getEntriesByType). Furthermore, in the _enrolled_ case, the script checks for the WebAssembly hooks marker to confirm that WEBCAT has indeed been executed. If that is not the case, the result is discarded and the iteration is repeated.

The tool uses [geckordp](https://github.com/jpramosi/geckordp), a library to use the Firefox Remote Debugging Protocol, and as such it is Firefox specific. Contrary to Chromium based browsers, Firefox cannot take an extension from the command line. Selenium and other automation tools either use the CDP API or Marionette, and as far as I could test, neither supported installing temporary addons. Thus, this method could be in the future the most convenient to also implement functional tests.

### Install
Firefox needs to be already installed.

```bash
python3 -m venv venv
. venv/bin.activate
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

Sample output:
```bash
python3 final.py --addon /Users/g/webcat/dist/webcat-extension.zip --iterations 10 --enrolled-url https://element.nym.re --non-enrolled-url https://webcat-element.pages.dev
Test URL                            Mode     Enrolled Addon    #        Elapsed 
https://element.nym.re              cold     true     true     10/10       307.4s
https://webcat-element.pages.dev    cold     false    true     10/10       304.8s
https://element.nym.re              cold     false    false    10/10       308.8s
https://element.nym.re              warm     true     true     10/10        50.9s
https://webcat-element.pages.dev    warm     false    true     10/10        51.2s
https://element.nym.re              warm     false    false    10/10        52.1s
```