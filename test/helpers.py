#!/usr/bin/env python3
import json
import uuid
import queue
import logging
import subprocess
import os
import ssl
import sys
import tempfile
import threading
import http.server
import socketserver
import hashlib
import datetime
import ipaddress
from base64 import b64decode, b64encode
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
    def __init__(self, override_firefox_path="", override_profiles_path="", additional_configs={}):
        self.host = "127.0.0.1"
        self.profile_name = f"geckordp-{uuid.uuid4()}"
        self.override_firefox_path = override_firefox_path
        self.pm = ProfileManager(override_firefox_path, override_profiles_path)
        self.pm.create(self.profile_name)
        profile = self.pm.get_profile_by_name(self.profile_name)
        self.profile_path = profile.path
        profile.set_required_configs()
        profile.set_config("browser.shell.checkDefaultBrowser", False)
        profile.set_config("browser.startup.couldRestoreSession.count", -1)
        for key, value in additional_configs.items():
            profile.set_config(key, value)
        logging.info(f"Profile {self.profile_name} created.")
        subprocess.Popen(["pkill", "-f", f'\\-P {self.profile_name}']) # TBB hack

    def start(self, headless=False, start="about:blank", flags=[], port=6000):
        self.port = port
        if headless:
            flags.append("-headless")
        Firefox.start(start, self.port, self.profile_name, flags, self.override_firefox_path, False)
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
            subprocess.Popen(["pkill", "-f", f'\\-p {self.profile_name}']) # TBB hack
            logging.info("Firefox process killed.")
        except:
            pass
        try:
            self.pm.remove(self.profile_name)
            logging.info(f"Profile {self.profile_name} removed.")
        except:
            pass

    def trust_cert(self, cert_path, port):
        """Add a certificate override for 127.0.0.1:port via cert_override.txt."""
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        der_data = cert.public_bytes(serialization.Encoding.DER)
        sha256 = hashlib.sha256(der_data).hexdigest()
        fingerprint = ":".join(sha256[i:i+2].upper() for i in range(0, len(sha256), 2))
        db_key = b64encode(der_data).decode("ascii")
        override_file = self.profile_path / "cert_override.txt"
        with open(override_file, "a") as f:
            f.write(f"127.0.0.1:{port}\tOID.2.16.840.1.101.3.4.2.1\t{fingerprint}\t{db_key}\n")

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

class TorBrowser(Browser): 
    class SecurityLevel:
        Standard = 4
        Safer = 2
        Safest = 1

        @staticmethod
        def _get_config(level):
            if level < TorBrowser.SecurityLevel.Safest or level > TorBrowser.SecurityLevel.Standard:
                raise RuntimeError(f"unrecognized security level '{level}'")
            defaults = {
                # https://gitlab.torproject.org/tpo/applications/tor-browser/-/blob/tor-browser-150.0a1-16.0-2/toolkit/components/securitylevel/SecurityLevel.sys.mjs?ref_type=heads#L253
                "javascript.options.ion":                   [ None, False, False, False,  True ],
                "javascript.options.baselinejit":           [ None, False, False, False,  True ],
                "javascript.options.native_regexp":         [ None, False, False, False,  True ],
                "mathml.disabled":                          [ None,  True,  True,  True, False ],
                "gfx.font_rendering.graphite.enabled":      [ None, False, False, False,  True ],
                "gfx.font_rendering.opentype_svg.enabled":  [ None, False, False, False,  True ],
                "svg.disabled":                             [ None,  True, False, False, False ],
                "javascript.options.asmjs":                 [ None, False, False, False, False ],
                "javascript.options.wasm":                  [ None,  True,  True,  True,  True ],
            }
            config = {
                "browser.security_level.security_slider": level,
                "browser.security_level.noscript_inited": False,
            }
            for key, values in defaults.items():
                config[key] = values[level]
            return config

    @staticmethod
    def get_binary_path():
        if sys.platform == "darwin":
            path = Path("/Applications/Tor Browser.app/Contents/MacOS/firefox")
            if path.exists():
                return path
            raise RuntimeError("Tor Browser.app not found in /Applications")
        try:
            return Path(subprocess.check_output(["which", "start-tor-browser"]).decode().strip())
        except subprocess.CalledProcessError:
            raise RuntimeError("'start-tor-browser' not found in $PATH")

    @staticmethod
    def get_profiles_path():
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "TorBrowser-Data" / "Browser"
        return Path(os.path.dirname(TorBrowser.get_binary_path())).joinpath("TorBrowser/Data/Browser/")

    def __init__(self, override_tbb_path="", override_profiles_path="", additional_configs={}, allowed_addons=[], security_level=4):
        if override_tbb_path == "":
            override_tbb_path = TorBrowser.get_binary_path()
        if override_profiles_path == "":
            override_profiles_path = TorBrowser.get_profiles_path()
        additional_configs["network.proxy.allow_hijacking_localhost"] = False
        if security_level != TorBrowser.SecurityLevel.Standard:
            additional_configs.update(TorBrowser.SecurityLevel._get_config(security_level))
        super().__init__(override_tbb_path, override_profiles_path, additional_configs)
        if len(allowed_addons) > 0:
            with open(self.profile_path.joinpath("extension-preferences.json"), "r") as file:
                prefs = json.load(file)
            for addon in allowed_addons:
                prefs[addon] = {
                    "permissions": ["internal:privateBrowsingAllowed"],
                    "origins": [],
                    "data_collection": []
                }
            with open(self.profile_path.joinpath("extension-preferences.json"), "w") as file:
                json.dump(prefs, file)

class Blob:
    def __init__(self, data, type="text/plain", base64=False):
        if base64:
            self.data = b64decode(data)
        else:
            self.data = data
        self.type = type

class Server:
    def __init__(self, root=".", headers=None, hooks=None, ssl_cert=None, ssl_key=None):
        self.root = os.path.abspath(root)
        self.headers = headers or {}
        self.hooks = hooks or {}
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.port = None

    def start(self):
        root, headers, hooks = self.root, self.headers, self.hooks

        class Handler(http.server.SimpleHTTPRequestHandler):
            def translate_path(self, path):
                return os.path.join(root, path.lstrip("/").split("?", 1)[0])

            def do_GET(self):
                if self.path in hooks:
                    self.send_response(200)
                    hook = hooks[self.path]
                    if type(hook) is bytes:
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(hook)
                    else:
                        self.send_header("Content-Type", hook.type)
                        self.end_headers()
                        self.wfile.write(hook.data)

                else:
                    super().do_GET()

            def end_headers(self):
                for k, v in headers.items(): self.send_header(k, v)
                super().end_headers()

            def log_message(self, *a): pass  # suppress logs

        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        if self.ssl_cert and self.ssl_key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.ssl_cert, self.ssl_key)
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.thread.join()

    def url(self):
        scheme = "https" if self.ssl_cert else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

def generate_ssl_cert(output_dir):
    """Generate a self-signed certificate for 127.0.0.1."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(output_dir, "cert.pem")
    key_path = os.path.join(output_dir, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return cert_path, key_path

class DB:
    hosts = {}

    def start(db):
        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/testing-list":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(db.hosts).encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *a): pass  # suppress logs

        db.httpd = socketserver.TCPServer(("127.0.0.1", 1234), Handler, False)
        db.httpd.allow_reuse_address = True
        db.httpd.server_bind()
        db.httpd.server_activate()
        db.thread = threading.Thread(target=db.httpd.serve_forever, daemon=True)
        db.thread.start()

    def stop(db):
        db.httpd.shutdown()
        db.thread.join()

    def set(db, host, hash):
        db.hosts[host] = hash
