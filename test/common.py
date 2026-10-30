import os
from helpers import Hook

class Fatal(Exception):
    pass

WEBCAT_ICON = Hook(
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAQAAAC1+jfqAAAABGdBTUEAALGPC/xhBQAAACBjSFJN"
    "AAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElN"
    "RQfoChYSHzod9YOfAAABNUlEQVQoz1XRv0ubARDG8c+bvMFW/BFfaAMupZWKgoPULQWXgg3orFBE"
    "cHNQ3Do46aJQFP8EB8Glg7qIOrjYuSKpguDiKNomaaEIaXw7vPZNfW457r4cd/dkNRXoUJBHXdws"
    "JsroM6Lgj0DoxqEz900gZ8KgfV8FfntiSEnZljpZMO6lNeeKlpwYVbfhvW7lZHyfT7rwzpVb0/bM"
    "I7KmPwHmlPDaqVjDN5tGQMk8tFlWwLr4IWqOvcVzKzoy8gIVL4yl5+7asSBS1ZDPCNBiRk8KjJpT"
    "MuVeIAjVMGM2/QiRCHfahaqhn35Y1Oqxjm1741oNel2kC8YavvjolU6rBv7xH1RS4LNnaLdgqjkw"
    "a9KlWOy7ojbDVkzKJS2IlR24FqsIFUV2HWn872aSP5WXU/UrcRL+AtouWZWI+tGIAAAAJXRFWHRk"
    "YXRlOmNyZWF0ZQAyMDI0LTEwLTIyVDE4OjIxOjM3KzAwOjAwXUyimQAAACV0RVh0ZGF0ZTptb2Rp"
    "ZnkAMjAyNC0xMC0yMlQxNDo1Mzo0MyswMDowMGXvS2oAAAAASUVORK5CYII=",
    type="image/png", base64=True)

BAD_WASM = Hook(
    "AGFzbQEAAAABCgJgAABgAn9/AX8DAwIAAQQFAXABAQEFBgEBggKCAgcRBAFhAgABYgAAAWMAAQFk"
    "AQAKCQICAAsEAEEACw==", type="application/wasm", base64=True)

[
    LOGENTRY_INLINE,
    LOGENTRY_ALERT,
    LOGENTRY_CSP,
    LOGENTRY_WASM_FETCH,
    LOGENTRY_WASM,
    LOGENTRY_IMPORT,
    LOGENTRY_LOAD_WORKER,
    LOGENTRY_LOAD_SHAREDWORKER,
    LOGENTRY_LOAD_WASMWORKER,
    LOGENTRY_LOAD_AUDIOWORKLET,
    LOGENTRY_WASM_FRAME,
    LOGENTRY_ERROR_SHAREDWORKER_ONERROR,
    LOGENTRY_ERROR_SHAREDWORKER_CALLBACK,
    LOGENTRY_ERROR_SHAREDWORKER_HANDLER,
    LOGENTRY_ERROR_WORKER_ONERROR,
    LOGENTRY_ERROR_WORKER_CALLBACK,
    LOGENTRY_ERROR_WORKER_HANDLER,
] = EXPECTED_LOGS = [
    ["inline:",True],
    ["alert.js:",True],
    ["csp.js",True],
    ["wasm_fetch.js:",True],
    ["wasm.js:",True],
    ["import.js",True],
    ["load_worker.js:",True],
    ["load_sharedworker.js:",True],
    ["load_wasmworker.js:",True],
    ["load_audioworklet.js:",True],
    ["wasm_frame.js:",True],
    ["Error: error in sharedworker", True, "onerror"],
    ["Error: error in sharedworker", True, "callback"],
    ["Error: error in sharedworker", True, "handler"],
    ["Error: error in worker", True, "onerror"],
    ["Error: error in worker", True, "callback"],
    ["Error: error in worker", True, "handler"],
]

EXPECTED_CSP = {
    "content-security-policy": "object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval' "
                               "'sha256-oiHtO61BAW24D+FpLSqz2Jnv6Wv67XDn90HOTlaklfQ='; "
                               "style-src 'self'; frame-src 'none'; worker-src 'self';"
}

FRAMEHOST_HOOK = {
    "/framehost.html": Hook(open("cases/testapp/framehost.html", "rb").read(), type="text/html", headers={
        "content-security-policy": "",
    }),
}

CSS_PATHS = set(map(lambda filename: f"/css/{filename}", os.listdir("./cases/testapp/css/")))
JS_PATHS = set(map(lambda filename: f"/js/{filename}", os.listdir("./cases/testapp/js/")))
WASM_PATHS = set(map(lambda filename: f"/wasm/{filename}", os.listdir("./cases/testapp/wasm/")))
WORKER_PATHS = set(map(lambda filename: f"/workers/{filename}", os.listdir("./cases/testapp/workers/")))
SERVICEWORKER_PATHS = set(filter(lambda path: "serviceworker" in path, WORKER_PATHS))
FRAME_PATHS = {"/js/framehost.js", "/wasm/frame_addThree.wasm"}
ALL_PATHS = {"/"}.union(CSS_PATHS,JS_PATHS,WASM_PATHS,WORKER_PATHS)
NON_FRAME_PATHS = ALL_PATHS-FRAME_PATHS

def setdiff(a: list, b: list):
    a = a.copy()
    for el in b:
        try:
            a.remove(el)
        except:
            pass
    return a
