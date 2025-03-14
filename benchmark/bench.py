#!/usr/bin/env python3
import argparse
from enum import Enum
import json
import sqlite3
import queue
import logging
import sys
import time
from time import sleep
from urllib.parse import quote
import subprocess
import uuid

# --- Patch subprocess.Popen to discard Firefox output ---
_original_popen = subprocess.Popen
def popen_no_output(args, **kwargs):
    if any("firefox" in str(arg).lower() for arg in args):
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    return _original_popen(args, **kwargs)
subprocess.Popen = popen_no_output
# ---------------------------------------------------------------

from geckordp.actors.addon.addons import AddonsActor
from geckordp.actors.descriptors.tab import TabActor
from geckordp.actors.root import RootActor
from geckordp.actors.web_console import WebConsoleActor
from geckordp.actors.events import Events
from geckordp.actors.targets.window_global import WindowGlobalActor
from geckordp.firefox import Firefox, _kill_instances
from geckordp.profile import ProfileManager
from geckordp.rdp_client import RDPClient

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

class Browser:
    def __init__(self, headless=False, start="about:blank", flags=[], port=6000):
        self.port = port
        self.host = "127.0.0.1"
        self.profile_name = f"geckordp-{uuid.uuid4()}"
        self.pm = ProfileManager()
        self.pm.create(self.profile_name)
        profile = self.pm.get_profile_by_name(self.profile_name)
        profile.set_required_configs()
        logging.info(f"Profile {self.profile_name} created.")
        if headless:
            flags.append("-headless")
        Firefox.start(start, self.port, self.profile_name, flags)
        logging.info("Firefox started.")
        self.client = RDPClient()
        self.client.connect(self.host, self.port)
        logging.info("RDP connection established.")
        self.root = RootActor(self.client)

    
    def destroy(self):
        self.client.disconnect()
        logging.info("RDP disconnected.")
        try:
            _kill_instances()
            logging.info("Firefox process killed.")
        except:
            pass
        self.pm.remove(self.profile_name)
        logging.info("Profile {self.profile_name} removed.")

    def install_extension(self, path):
        root_actor_ids = self.root.get_root()
        addons = [addon for addon in self.root.list_addons() if path in addon.get("url", "")]
        if not addons:
            logging.info(f"Installing temporary addon from {path}")
            response = AddonsActor(self.client, root_actor_ids["addonsActor"]).install_temporary_addon(path)
            addon_id = response.get("id")
            if addon_id is None:
                logging.error(f"Addon failed to load:\n{json.dumps(response, indent=2)}")
                return None
            logging.info(f"Addon {addon_id} installed.")
            return addon_id
        else:
            logging.info("Addon already installed")
            return addons[0].get("id")

    def navigate(self, url):
        current_tab = self.root.current_tab()
        tab = TabActor(self.client, current_tab["actor"])
        actor_ids = tab.get_target()
        web = WindowGlobalActor(self.client, actor_ids["actor"])
        logging.info(f"Navigating to {url}")
        return web.navigate_to(url)
    
    def execute(self, javascript):
        current_tab = self.root.current_tab()
        tab = TabActor(self.client, current_tab["actor"])
        actor_ids = tab.get_target()
        console_actor_id = actor_ids["consoleActor"]

        logging.info(f"Executing js...")
        return self.evaluate_js_sync(console_actor_id, javascript)

    def evaluate_js_sync(self, console_actor_id, code, timeout=10):
        """
        Evaluates JavaScript asynchronously via the WebConsoleActor, waits for a result,
        then extracts the returned JSON string and parses it.
        """
        result_queue = queue.Queue()

        def on_eval(data):
            result_queue.put(data)

        self.client.add_event_listener(console_actor_id, Events.WebConsole.EVALUATION_RESULT, on_eval)
        console = WebConsoleActor(self.client, console_actor_id)
        console.start_listeners([])
        console.evaluate_js_async(code)
        eval_result = result_queue.get(timeout=timeout)

        result_field = eval_result.get("result")
        if isinstance(result_field, dict) and "value" in result_field:
            value = result_field["value"]
        else:
            value = result_field
        try:
            parsed = json.loads(value)
            return parsed
        except Exception as e:
            print("Error parsing JS evaluation result:", e)
            return {}

class PerformanceTester:
    def __init__(self, url, url_wait=2, scenario=Scenario.COLD, enrolled=False, iterations=1, addon_path=None, addon_wait=10, marker="webcat_executed", headless=False):
        self.url = url
        self.url_wait = url_wait
        self.iterations = iterations
        self.scenario = scenario
        self.enrolled = enrolled
        self.addon_path = addon_path
        self.addon_wait = 10
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

    def setup_browser(self):
        browser = Browser(self.headless)
        if self.addon_path:
            try:
                browser.install_extension(self.addon_path)
            except:
                raise ValueError(f"{self.addon_path} does not exists or is not a valid addon.")
        sleep(self.addon_wait)
        return browser

    def run_test(self):
        start = time.time()
        cursor = self.conn.cursor()
        # Warm up cache for warm test
        if self.scenario == Scenario.WARM:
            browser = self.setup_browser()
            browser.navigate(self.url)
            sleep(self.url_wait)
        
        i = 1
        while i <= self.iterations:
            print(f"{self.url:35} {self.scenario.value:8} {"true" if self.enrolled else "false":8} {"true" if self.addon_path else "false":8} {f'{i}/{self.iterations}':8} {time.time()-start:8.1f}s", end='\r')
            if self.scenario == Scenario.COLD:
                browser = browser = self.setup_browser()
            
            browser.navigate(self.url)
            sleep(self.url_wait)

            result = browser.execute(js_code)

            if self.enrolled and self.addon_path:
                if not result.get(self.marker, False):
                    continue
            
            cursor.execute("INSERT INTO results (scenario, extension, enrolled, url, sequence, timestamp, json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self.scenario.value, 1 if self.addon_path else 0, self.enrolled, self.url, i, time.time(), json.dumps(result)))
            self.conn.commit()
            #print(result)

            i += 1
            if self.scenario == Scenario.COLD:
                browser.destroy()
        
        if self.scenario == Scenario.WARM:
            browser.destroy()
        print()

def main():
    parser = argparse.ArgumentParser(
        description="Performance tester with full suite mode for enrolled and non-enrolled domains."
    )
    parser.add_argument("--addon", type=str, help="Path to the temporary addon", required=True)
    parser.add_argument("--iterations", type=int, default=1, help="Number of iterations per test", required=True)
    parser.add_argument("--enrolled-url", type=str, help="URL for the enrolled domain", required=True)
    parser.add_argument("--non-enrolled-url", type=str, help="URL for the non-enrolled domain", required=True)
    parser.add_argument("--headless", type=bool, help="Headless mode", default=False)
    args = parser.parse_args()

    #logger = logging.getLogger()
    #formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    #logger.setLevel(logging.INFO)

    logging.disable(logging.CRITICAL)

    print(f"{'Test URL':35} {'Mode':8} {'Enrolled':8} {'Addon':8} {'#':8} {'Elapsed':8}")

    for scenario in Scenario:
        # Enrolled addon
        PerformanceTester(args.enrolled_url, 2, scenario, True, args.iterations, args.addon, 10, "webcat_executed", args.headless).run_test()
        # Non-enrolled addon
        PerformanceTester(args.non_enrolled_url, 2, scenario, False, args.iterations, args.addon, 10, "webcat_executed", args.headless).run_test()
        # No addon
        PerformanceTester(args.enrolled_url, 2, scenario, False, args.iterations, headless=args.headless).run_test()

main()