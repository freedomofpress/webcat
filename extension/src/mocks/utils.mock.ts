export * from "../webcat/utils";

import { SHA256 as realSHA256 } from "../webcat/utils";

// Overrides SHA256 function with a throwing one when the test marker
// is found
const FAIL_CLOSED_TRIGGER = new TextEncoder().encode(
  "__WEBCAT_TEST_FAIL_CLOSED__",
);

function containsTrigger(view: Uint8Array): boolean {
  outer: for (let i = 0; i <= view.length - FAIL_CLOSED_TRIGGER.length; i++) {
    for (let j = 0; j < FAIL_CLOSED_TRIGGER.length; j++) {
      if (view[i + j] !== FAIL_CLOSED_TRIGGER[j]) continue outer;
    }
    return true;
  }
  return false;
}

export async function SHA256(
  data: ArrayBuffer | Uint8Array | string,
): Promise<ArrayBuffer> {
  let view: Uint8Array;
  if (typeof data === "string") {
    view = new TextEncoder().encode(data);
  } else if (data instanceof Uint8Array) {
    view = data;
  } else {
    view = new Uint8Array(data);
  }
  if (containsTrigger(view)) {
    console.log(
      "[TESTING] utils mock SHA256 — throwing to exercise failClosed",
    );
    throw new Error("[TESTING] fail-closed trigger");
  }
  return realSHA256(data);
}
