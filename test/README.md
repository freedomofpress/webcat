# webcat integration tests

## Prerequisites

- Python 3
- Firefox
- Tor Browser (optional, for Tor tests)

### Linux

Install Firefox via your package manager. For Tor Browser, ensure `start-tor-browser` is in your `$PATH`.

### macOS

Install Firefox normally. For Tor Browser, install it to `/Applications/Tor Browser.app`.

## Running tests

```bash
make test
```

### Headless mode

Run without a visible browser window:

```bash
HEADLESS=1 make test
```

### Running only Firefox or Tor tests

Tests are parametrized across `firefox` and `tor` browsers. Use `-k` to filter:

```bash
# Firefox only
cd test && .venv/bin/pytest -v tests.py --addon ../dist/webcat-extension-test.zip -k firefox

# Tor only
cd test && .venv/bin/pytest -v tests.py --addon ../dist/webcat-extension-test.zip -k tor
```

### Running a specific test

```bash
cd test && .venv/bin/pytest -v tests.py --addon ../dist/webcat-extension-test.zip -k "test_webcat and firefox"
```

### Extra pytest arguments

Pass additional arguments via `TESTARGS`:

```bash
make test TESTARGS="--addon ../dist/webcat-extension-test.zip -k firefox --headless"
```