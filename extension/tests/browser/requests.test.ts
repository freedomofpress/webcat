import { beforeEach, describe, expect, it } from "vitest";

import { BlockingResponse } from "../../src/browser/requests";

describe("BlockingResponse", () => {
  let br: BlockingResponse;

  beforeEach(() => {
    br = new BlockingResponse();
  });

  it("should block until disposed in all scopes", async () => {
    const events = [];
    {
      events.push("entering sync scope");
      using _disposable = br;
      {
        events.push("entering nested scope");
        using _disposable = br;
        events.push("exiting nested scope");
      }
      (async () => {
        events.push("entering async scope");
        using _disposable = br;
        await new Promise((resolve) => {
          setTimeout(resolve, 100);
        });
        (async () => {
          events.push("entering nested async scope");
          using _disposable = br;
          await new Promise((resolve) => {
            setTimeout(resolve, 100);
          });
          events.push("exiting nested async scope");
        })();
        events.push("exiting async scope");
      })();
      events.push("exiting sync scope");
    }
    events.push("calling ready()");
    br.ready().then(() => events.push("resolved"));

    await expect(br.ready()).resolves.toBe(br);
    expect(events).toEqual([
      "entering sync scope",
      "entering nested scope",
      "exiting nested scope",
      "entering async scope",
      "exiting sync scope",
      "calling ready()",
      "entering nested async scope",
      "exiting async scope",
      "exiting nested async scope",
      "resolved",
    ]);
  });

  it("should not block when not used as a disposable", () => {
    expect(br.ready()).resolves.toBe(br);
  });

  it("should copy properties from any object passed to set", () => {
    const original = {
      responseHeaders: [{ name: "Server", value: "nginx" }],
      requestHeaders: [{ name: "X-Requested-With", value: "XMLHttpRequest" }],
      redirectUrl: "https://example.com/",
      cancal: false,
    };
    br.set(original);
    expect(br).toEqual(original);
  });
});
