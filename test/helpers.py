#!/usr/bin/env python3
import json
import uuid
import queue
import logging
import subprocess
import os
import threading
import http.server
import socketserver

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
        try:
            self.pm.remove(self.profile_name)
            logging.info("Profile {self.profile_name} removed.")
        except:
            pass

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

        return value


class Server:
    def __init__(self, root=".", headers=None, hooks=None):
        self.root = os.path.abspath(root)
        self.headers = headers or {}
        self.hooks = hooks or {}
        self.port = None

    def start(self):
        root, headers, hooks = self.root, self.headers, self.hooks

        class Handler(http.server.SimpleHTTPRequestHandler):
            def translate_path(self, path):
                return os.path.join(root, path.lstrip("/").split("?", 1)[0])

            def do_GET(self):
                if self.path in hooks:
                    self.send_response(200)
                    for k, v in headers.items(): self.send_header(k, v)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(hooks[self.path])
                else:
                    super().do_GET()

            def end_headers(self):
                for k, v in headers.items(): self.send_header(k, v)
                super().end_headers()

            def log_message(self, *a): pass  # suppress logs

        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.thread.join()

    def url(self): return f"http://127.0.0.1:{self.port}"
