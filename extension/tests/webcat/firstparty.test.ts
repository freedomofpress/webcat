import { describe, expect, it } from "vitest";

import { BeforeRequestDetails } from "../../src/browser/requests";
import {
  isThirdPartyWorkerScript,
  resolveFirstParty,
} from "../../src/webcat/firstparty";

const request = (fields: Partial<BeforeRequestDetails>) =>
  ({
    requestId: "r",
    tabId: 7,
    frameId: 0,
    type: "script",
    ...fields,
  }) as never;

// A tab showing embedder.example, which embeds enrolled.example, which in
// turn has a srcdoc frame
const tab = async () => [
  { frameId: 0, url: "https://embedder.example/page" },
  { frameId: 5, url: "https://enrolled.example/" },
  { frameId: 6, url: "about:srcdoc" },
];
const noLookup = () =>
  Promise.reject(new Error("frames must not be looked up"));

describe("resolveFirstParty: requests with frame ancestors", () => {
  it("uses the topmost ancestor", async () => {
    await expect(
      resolveFirstParty(
        request({
          url: "https://enrolled.example/app.js",
          frameId: 5,
          frameAncestors: [
            { url: "https://middle.example/", frameId: 3 },
            { url: "https://embedder.example/page", frameId: 0 },
          ],
        }),
        noLookup,
      ),
    ).resolves.toBe("https://embedder.example");
  });

  it("covers a worker script created by a framed document", async () => {
    await expect(
      resolveFirstParty(
        request({
          url: "https://enrolled.example/workers/worker.js",
          documentUrl: "https://enrolled.example/",
          frameId: 5,
          frameAncestors: [
            { url: "https://embedder.example/page", frameId: 0 },
          ],
        }),
        noLookup,
      ),
    ).resolves.toBe("https://embedder.example");
  });

  it("gives a request under an opaque top-level document a partition of its own", async () => {
    await expect(
      resolveFirstParty(
        request({
          url: "https://enrolled.example/app.js",
          frameId: 5,
          frameAncestors: [{ url: "about:blank", frameId: 0 }],
        }),
        noLookup,
      ),
    ).resolves.toBe("r");
  });

  it("treats an empty ancestor list as no ancestors (Firefox 155+ worker loads)", async () => {
    await expect(
      resolveFirstParty(
        request({
          url: "https://enrolled.example/workers/import.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
          frameId: 5,
          frameAncestors: [],
        }),
        tab,
      ),
    ).resolves.toBe("https://embedder.example");
  });
});

describe("resolveFirstParty: top-level navigations", () => {
  it("uses the request URL, never the tab's current document", async () => {
    await expect(
      resolveFirstParty(
        request({ type: "main_frame", url: "https://enrolled.example/" }),
        noLookup,
      ),
    ).resolves.toBe("https://enrolled.example");
  });
});

describe("resolveFirstParty: tab-bound requests without ancestors", () => {
  it("uses the top frame for a top-level document's own subresource", async () => {
    await expect(
      resolveFirstParty(
        request({
          tabId: 8,
          url: "https://enrolled.example/app.js",
          documentUrl: "https://enrolled.example/",
        }),
        async () => [{ frameId: 0, url: "https://enrolled.example/" }],
      ),
    ).resolves.toBe("https://enrolled.example");
  });

  it("uses the top frame for a worker import reported under frameId 0 (Firefox ESR)", async () => {
    await expect(
      resolveFirstParty(
        request({
          url: "https://enrolled.example/workers/import.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
        }),
        tab,
      ),
    ).resolves.toBe("https://embedder.example");
  });

  it("uses the top frame for a worker import attributed to its frame (Firefox 155+)", async () => {
    await expect(
      resolveFirstParty(
        request({
          frameId: 5,
          url: "https://enrolled.example/workers/import.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
        }),
        tab,
      ),
    ).resolves.toBe("https://embedder.example");
  });

  it("uses the top frame for a nested worker reported without a frame (Firefox 155+)", async () => {
    await expect(
      resolveFirstParty(
        request({
          frameId: -1,
          url: "https://enrolled.example/workers/nested.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
        }),
        tab,
      ),
    ).resolves.toBe("https://embedder.example");
  });

  it("finds the owner of a worker created in a srcdoc frame through its parent frame", async () => {
    await expect(
      resolveFirstParty(
        request({
          frameId: 6,
          url: "https://enrolled.example/workers/import.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
        }),
        tab,
      ),
    ).resolves.toBe("https://embedder.example");
  });

  it("keeps the first party across a same-origin navigation of the tab", async () => {
    await expect(
      resolveFirstParty(
        request({
          tabId: 8,
          url: "https://enrolled.example/workers/import.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
        }),
        async () => [{ frameId: 0, url: "https://enrolled.example/other" }],
      ),
    ).resolves.toBe("https://enrolled.example");
  });

  it("attributes a request to the next site when that site embeds the owner", async () => {
    // The partition a genuine visit of enrolled.example under other.example
    // would create anyway
    await expect(
      resolveFirstParty(
        request({
          url: "https://enrolled.example/workers/import.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
        }),
        async () => [
          { frameId: 0, url: "https://other.example/" },
          { frameId: 9, url: "https://enrolled.example/" },
        ],
      ),
    ).resolves.toBe("https://other.example");
  });

  it("gives a request under an opaque top frame a partition of its own", async () => {
    await expect(
      resolveFirstParty(
        request({
          frameId: 5,
          url: "https://enrolled.example/workers/import.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
        }),
        async () => [
          { frameId: 0, url: "about:blank" },
          { frameId: 5, url: "https://enrolled.example/" },
        ],
      ),
    ).resolves.toBe("r");
  });

  it.each([
    ["the tab is gone", () => Promise.reject(new Error("Invalid tab ID"))],
    ["the tab was discarded", async () => null],
    [
      "the frame is gone",
      async () => [{ frameId: 0, url: "https://embedder.example/page" }],
    ],
    [
      "the owning document left the tab",
      async () => [{ frameId: 0, url: "https://other.example/" }],
    ],
    [
      "the owning document left the tab and the request has no frame",
      async () => [{ frameId: 0, url: "https://other.example/" }],
      -1,
    ],
  ])("throws when %s", async (_, frames, frameId = 5) => {
    await expect(
      resolveFirstParty(
        request({
          frameId,
          url: "https://enrolled.example/workers/import.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
        }),
        frames,
      ),
    ).rejects.toThrow();
  });
});

describe("resolveFirstParty: tab-less requests", () => {
  it.each([
    [
      "a SharedWorker script",
      "https://enrolled.example/workers/shared.js",
      "https://enrolled.example/",
    ],
    [
      "a script imported by a SharedWorker",
      "https://enrolled.example/workers/import.js",
      "https://enrolled.example/workers/shared.js",
    ],
    [
      "a ServiceWorker script",
      "https://enrolled.example/workers/sw.js",
      "https://enrolled.example/",
    ],
    [
      "a fetch from a ServiceWorker to another site",
      "https://other.example/data.json",
      "https://enrolled.example/workers/sw.js",
    ],
  ])("uses documentUrl for %s", async (_, url, documentUrl) => {
    await expect(
      resolveFirstParty(
        request({ tabId: -1, frameId: -1, url, documentUrl }),
        noLookup,
      ),
    ).resolves.toBe("https://enrolled.example");
  });

  it("uses documentUrl for a ServiceWorker of a frame granted storage access, which the browser reports first-party", async () => {
    await expect(
      resolveFirstParty(
        request({
          tabId: -1,
          frameId: -1,
          thirdParty: false,
          url: "https://enrolled.example/workers/sw.js",
          documentUrl: "https://enrolled.example/",
        }),
        noLookup,
      ),
    ).resolves.toBe("https://enrolled.example");
  });

  it("uses the request's own origin for a document-less request the browser reports first-party", async () => {
    await expect(
      resolveFirstParty(
        request({
          tabId: -1,
          frameId: -1,
          thirdParty: false,
          url: "https://enrolled.example/workers/sw.js",
        }),
        noLookup,
      ),
    ).resolves.toBe("https://enrolled.example");
  });

  it("throws for a document-less request with no third-party flag at all", async () => {
    await expect(
      resolveFirstParty(
        request({
          tabId: -1,
          frameId: -1,
          url: "https://enrolled.example/workers/sw.js",
        }),
        noLookup,
      ),
    ).rejects.toThrow();
  });

  it("throws for a document-less request the browser reports third-party", async () => {
    await expect(
      resolveFirstParty(
        request({
          tabId: -1,
          frameId: -1,
          thirdParty: true,
          url: "https://enrolled.example/workers/sw.js",
        }),
        noLookup,
      ),
    ).rejects.toThrow();
  });
});

describe("isThirdPartyWorkerScript", () => {
  const script = {
    tabId: -1,
    frameId: -1,
    thirdParty: true,
    url: "https://enrolled.example/workers/shared.js",
    documentUrl: "https://enrolled.example/",
  };

  it("matches a SharedWorker or ServiceWorker script loading in a third-party context", () => {
    expect(isThirdPartyWorkerScript(request(script))).toBe(true);
  });

  it("matches a worker script with no third-party flag at all", () => {
    expect(
      isThirdPartyWorkerScript(request({ ...script, thirdParty: undefined })),
    ).toBe(true);
  });

  it("does not match a first-party worker script", () => {
    expect(
      isThirdPartyWorkerScript(request({ ...script, thirdParty: false })),
    ).toBe(false);
  });

  it("does not match a first-party worker fetching another site", () => {
    expect(
      isThirdPartyWorkerScript(
        request({ ...script, url: "https://other.example/data.json" }),
      ),
    ).toBe(false);
  });

  it("does not match a request with no document", () => {
    expect(
      isThirdPartyWorkerScript(request({ ...script, documentUrl: undefined })),
    ).toBe(false);
  });

  it("does not match a request bound to a tab", () => {
    expect(isThirdPartyWorkerScript(request({ ...script, tabId: 7 }))).toBe(
      false,
    );
  });
});
