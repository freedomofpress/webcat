import { beforeEach, describe, expect, it, vi } from "vitest";

import { ContentScript } from "../../src/browser/scripting";

const mockScripting = {
  getRegisteredContentScripts: vi.fn(),
  registerContentScripts: vi.fn(),
  unregisterContentScripts: vi.fn(),
};

(globalThis as Record<string, unknown>).browser = {
  scripting: mockScripting,
};

describe("ContentScript", () => {
  let cs: ContentScript;
  let registeredScripts: Map<
    string,
    {
      matches: string[];
    }
  >;

  beforeEach(() => {
    registeredScripts = new Map();
    mockScripting.getRegisteredContentScripts.mockImplementation(() => {
      return Promise.resolve(Array.from(registeredScripts.values()));
    });
    cs = new ContentScript("/scripts.js");
  });

  it("should register new content scripts", async () => {
    await cs.bind(["example.com", "webcat.tech"]);
    expect(mockScripting.registerContentScripts).toHaveBeenCalledWith([
      {
        id: expect.any(String),
        js: ["/scripts.js"],
        matches: ["http://example.com/*", "https://example.com/*"],
        matchOriginAsFallback: true,
        allFrames: true,
        runAt: "document_start",
      },
      {
        id: expect.any(String),
        js: ["/scripts.js"],
        matches: ["http://webcat.tech/*", "https://webcat.tech/*"],
        matchOriginAsFallback: true,
        allFrames: true,
        runAt: "document_start",
      },
    ]);
  });

  it("should unregister removed content scripts", async () => {
    await cs.bind(["example.com", "example.org", "webcat.tech"]);
    await cs.bind(["example.org"]);
    expect(mockScripting.unregisterContentScripts).toHaveBeenCalledWith({
      ids: Array.from(registeredScripts.keys()).filter((key) =>
        ["http://example.com/*", "http://webcat.tech/*"].includes(
          registeredScripts.get(key)?.matches[0] as string,
        ),
      ),
    });
  });

  it("should register added content scripts", async () => {
    await cs.bind(["example.com", "webcat.tech"]);
    await cs.bind(["example.org"]);
    expect(mockScripting.registerContentScripts).toHaveBeenCalledWith([
      {
        id: expect.any(String),
        js: ["/scripts.js"],
        matches: ["http://example.org/*", "https://example.org/*"],
        matchOriginAsFallback: true,
        allFrames: true,
        runAt: "document_start",
      },
    ]);
  });
});
