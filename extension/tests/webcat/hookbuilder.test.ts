import { describe, expect, it, vi } from "vitest";

import { HookBuilder } from "../../src/webcat/hookbuilder";
import { WebcatUI } from "../../src/webcat/ui";

vi.mock("../../dist/hooks/content.js?raw", () => ({
  default: `content {{ "__DATA_PLACEHOLDER__" }}`,
}));
vi.mock("../../dist/hooks/page.js?raw", () => ({
  default: `page {{ "__DATA_PLACEHOLDER__" }}`,
}));

vi.mock("../../src/browser/permissions", () => ({
  default: {
    require: vi.fn().mockReturnValue(vi.fn()),
  },
}));

vi.stubGlobal("browser", {
  runtime: {
    onConnect: {
      addListener: vi.fn(),
    },
  },
});

describe("HookBuilder", () => {
  const hb = new HookBuilder({} as WebcatUI, {
    staticHookPath: "hooks.js",
    connectionName: "conn",
  });

  it("should embed inputs into page hooks", async () => {
    await expect(hb.getPageHooks(["abc"])).resolves.toBe(
      `page {{ {"hashes":["abc"],"connectionName":"conn"} }}`,
    );
  });

  it("should embed inputs into content script hooks", async () => {
    await expect(hb.getContentScriptHooks(["abc"])).resolves.toStrictEqual([
      expect.any(Function),
      ['{"hashes":["abc"],"connectionName":"conn"}'],
    ]);
  });
});
