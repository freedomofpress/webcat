#!/usr/bin/env python3
import argparse
from enum import Enum
import json
import sqlite3
import logging
import time
import os
from time import sleep

from helpers import Browser, Server

class Scenario(Enum):
    COLD = "cold"
    WARM = "warm"

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

class PerformanceTester:
    def __init__(self, root, headers, host, url_wait=2, scenario=Scenario.COLD, enrolled=False, iterations=1, addon_path=None, addon_wait=10, marker="webcat_executed", headless=False):
        self.root = root
        self.headers = headers or {}
        self.host = host
        self.url_wait = url_wait
        self.iterations = iterations
        self.scenario = scenario
        self.enrolled = enrolled
        self.addon_path = addon_path
        self.addon_wait = addon_wait
        self.marker = marker
        self.headless = headless
        self.conn = self._create_db()

    def _create_db(self):
        conn = sqlite3.connect("results.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario TEXT,
                extension INTEGER,
                enrolled INTEGER,
                url TEXT,
                sequence INTEGER,
                timestamp TEXT,
                json TEXT
            )
        """)
        conn.commit()
        return conn

    def run_test(self):
        start = time.time()
        cursor = self.conn.cursor()
        srv = Server(root=self.root, headers=self.headers)
        srv.start()
        url = f"http://{self.host}:{srv.port}/"

        def setup_browser():
            browser = Browser(self.headless)
            if self.addon_path:
                try:
                    browser.install_extension(self.addon_path)
                except:
                    raise ValueError(f"{self.addon_path} does not exist or is not a valid addon.")
            sleep(self.addon_wait)
            return browser

        if self.scenario == Scenario.WARM:
            browser = setup_browser()
            browser.navigate(url)
            sleep(self.url_wait)

        i = 1
        while i <= self.iterations:
            print(f"{url:50} {self.scenario.value:8} {'true' if self.enrolled else 'false':8} {'true' if self.addon_path else 'false':8} {f'{i}/{self.iterations}':8} {time.time()-start:8.1f}s", end='\r')
            if self.scenario == Scenario.COLD:
                browser = setup_browser()

            browser.navigate(url)
            sleep(self.url_wait)

            result_raw = browser.execute(js_code)
            try:
                result = json.loads(result_raw)
            except Exception as e:
                print("Error parsing JS result:", result_raw)
                result = {}

            if self.enrolled and self.addon_path:
                if not result.get(self.marker, False):
                    continue

            cursor.execute("INSERT INTO results (scenario, extension, enrolled, url, sequence, timestamp, json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self.scenario.value, 1 if self.addon_path else 0, self.enrolled, url, i, time.time(), json.dumps(result)))
            self.conn.commit()

            i += 1
            if self.scenario == Scenario.COLD:
                browser.destroy()

        if self.scenario == Scenario.WARM:
            browser.destroy()
        srv.stop()
        print()

def main():
    parser = argparse.ArgumentParser(description="Performance tester with full suite mode for enrolled and non-enrolled domains.")
    parser.add_argument("--addon", type=str, help="Path to the temporary addon", required=True)
    parser.add_argument("--iterations", type=int, help="Number of iterations per test", default=20)
    parser.add_argument("--root", type=str, help="Document root to serve static files from", default="cases/element")
    parser.add_argument("--headless", type=bool, help="Headless mode", default=False)
    args = parser.parse_args()

    logging.disable(logging.CRITICAL)

    abs_path = os.path.abspath(args.addon)
    if not os.path.exists(abs_path):
        print(f"Error: Addon path does not exist: {abs_path}")
        exit(1)

    headers = {
        "x-sigstore-signers": '[{"identity": "giulio@freedom.press", "issuer": "https://accounts.google.com"}, {"identity": "cory@freedom.press", "issuer": "https://accounts.google.com"}, {"identity": "github@lsd.cat", "issuer": "https://github.com/login/oauth"}]',
        "x-sigstore-threshold": "2",
        "content-security-policy": "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; img-src * blob: data:; connect-src * blob:; font-src 'self' data: ; media-src * blob: data:; child-src blob: data:; worker-src 'self'; frame-src blob: data:; form-action 'self'; manifest-src 'self'; frame-ancestors 'self'"
    }

    print(f"{'Test URL':50} {'Mode':8} {'Enrolled':8} {'Addon':8} {'#':8} {'Elapsed':8}")

    for scenario in Scenario:
        # Enrolled addon (served via 127.0.0.1)
        PerformanceTester(args.root, headers, "127.0.0.1", 2, scenario, True, args.iterations, abs_path, 10, "webcat_executed", args.headless).run_test()
        # Non-enrolled addon (served via localhost)
        PerformanceTester(args.root, headers, "localhost", 2, scenario, False, args.iterations, abs_path, 10, "webcat_executed", args.headless).run_test()
        # No addon (served via 127.0.0.1)
        PerformanceTester(args.root, headers, "127.0.0.1", 2, scenario, False, args.iterations, headless=args.headless).run_test()

if __name__ == "__main__":
    main()
