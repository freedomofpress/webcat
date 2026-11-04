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

const tab = async () => [
  { frameId: 0, url: "https://embedder.example/page" },
  { frameId: 5, url: "https://enrolled.example/" },
  { frameId: 6, url: "about:srcdoc" },
];

describe("resolveFirstParty", () => {
  it("uses the topmost ancestor of a framed request", async () => {
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
      ),
    ).resolves.toBe("r");
  });

  it("uses the request URL of a top-level navigation", async () => {
    await expect(
      resolveFirstParty(
        request({ type: "main_frame", url: "https://enrolled.example/" }),
      ),
    ).resolves.toBe("https://enrolled.example");
  });

  it("uses the tab's top frame for a worker import reported under frameId 0 (Firefox ESR)", async () => {
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

  it("uses the tab's top frame for a nested worker reported without a frame (Firefox 155+)", async () => {
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
  ])("throws for a tab-bound request when %s", async (_, frames) => {
    await expect(
      resolveFirstParty(
        request({
          frameId: 5,
          url: "https://enrolled.example/workers/import.js",
          documentUrl: "https://enrolled.example/workers/worker.js",
        }),
        frames,
      ),
    ).rejects.toThrow();
  });

  it("uses documentUrl for a tab-less worker script", async () => {
    await expect(
      resolveFirstParty(
        request({
          tabId: -1,
          frameId: -1,
          url: "https://enrolled.example/workers/shared.js",
          documentUrl: "https://enrolled.example/",
        }),
      ),
    ).resolves.toBe("https://enrolled.example");
  });

  it("uses the request's own origin for a document-less request the browser reports as first-party", async () => {
    await expect(
      resolveFirstParty(
        request({
          tabId: -1,
          frameId: -1,
          thirdParty: false,
          url: "https://enrolled.example/workers/sw.js",
        }),
      ),
    ).resolves.toBe("https://enrolled.example");
  });

  it("throws for a document-less request the browser reports as third-party", async () => {
    await expect(
      resolveFirstParty(
        request({
          tabId: -1,
          frameId: -1,
          thirdParty: true,
          url: "https://enrolled.example/workers/sw.js",
        }),
      ),
    ).rejects.toThrow();
  });
});

describe("isThirdPartyWorkerScript", () => {
  const tabless = {
    tabId: -1,
    frameId: -1,
    thirdParty: true,
    url: "https://enrolled.example/workers/shared.js",
  };

  it("matches a worker script loading in a third-party context", () => {
    expect(
      isThirdPartyWorkerScript(
        request({ ...tabless, documentUrl: "https://enrolled.example/" }),
      ),
    ).toBe(true);
  });

  it("does not match a first-party worker fetching another site", () => {
    expect(
      isThirdPartyWorkerScript(
        request({ ...tabless, documentUrl: "https://other.example/sw.js" }),
      ),
    ).toBe(false);
  });

  it("does not match a request bound to a tab", () => {
    expect(
      isThirdPartyWorkerScript(
        request({
          ...tabless,
          tabId: 7,
          documentUrl: "https://enrolled.example/",
        }),
      ),
    ).toBe(false);
  });
});
