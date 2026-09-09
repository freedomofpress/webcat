import { beforeEach, describe, expect, it, Mock, vi } from "vitest";

vi.hoisted(() => {
  vi.stubGlobal("browser", {
    permissions: {
      onAdded: {
        addListener: vi.fn(),
      },
      onRemoved: {
        addListener: vi.fn(),
      },
      contains: vi.fn(),
    },
  });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockOnAdded = (globalThis as any).browser.permissions.onAdded
  .addListener as Mock<Procedure>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockOnRemoved = (globalThis as any).browser.permissions.onRemoved
  .addListener as Mock<Procedure>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockContains = (globalThis as any).browser.permissions
  .contains as Mock<Procedure>;

import { Procedure } from "@vitest/spy";

import { PermissionChecker } from "../../src/browser/permissions";

function thenable<T>(t: T) {
  return {
    then: (f: (t: T) => void) => f(t),
  };
}

describe("PermissionChecker", () => {
  let permissions: PermissionChecker;
  let onAdded: () => void;
  let onRemoved: () => void;
  beforeEach(() => {
    vi.resetAllMocks();
    mockOnAdded.mockImplementationOnce((f: typeof onAdded) => {
      onAdded = f;
    });
    mockOnRemoved.mockImplementationOnce((f: typeof onRemoved) => {
      onRemoved = f;
    });
    permissions = new PermissionChecker();
  });

  it("calls the permissions API correctly with a named permission", () => {
    mockContains.mockResolvedValueOnce(true);
    permissions.require("webRequest")(class Class {});
    expect(mockContains).toHaveBeenCalledExactlyOnceWith({
      origins: [],
      permissions: ["webRequest"],
    });
  });

  it("calls the permissions API correctly with a host permission", () => {
    mockContains.mockResolvedValueOnce(true);
    permissions.require("https://example.com/*")(class Class {});
    expect(mockContains).toHaveBeenCalledExactlyOnceWith({
      origins: ["https://example.com/*"],
      permissions: [],
    });
  });

  it("calls the permissions API correctly with the <all_urls> permission", () => {
    mockContains.mockResolvedValueOnce(true);
    permissions.require("<all_urls>")(class Class {});
    expect(mockContains).toHaveBeenCalledExactlyOnceWith({
      origins: ["<all_urls>"],
      permissions: [],
    });
  });

  it("triggers an error event when a required permission is missing", () => {
    mockContains.mockReturnValueOnce(thenable(false));

    const cb = vi.fn();
    permissions.addEventListener("permissionerror", cb);
    permissions.addEventListener("permissionrestored", cb);
    permissions.require("foo")(class Class {});

    expect(cb).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ type: "permissionerror" }),
    );
  });

  it("does not trigger any event when no permission is missing", () => {
    mockContains.mockReturnValueOnce(thenable(true));

    const cb = vi.fn();
    permissions.addEventListener("permissionerror", cb);
    permissions.addEventListener("permissionrestored", cb);
    permissions.require("foo")(class Class {});

    expect(cb).not.toHaveBeenCalled();
  });

  it("triggers a restore event when a required permission is added", () => {
    mockContains.mockReturnValueOnce(thenable(false));

    const cb = vi.fn();
    permissions.addEventListener("permissionerror", cb);
    permissions.addEventListener("permissionrestored", cb);
    permissions.require("foo")(class Class {});

    expect(cb).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ type: "permissionerror" }),
    );

    cb.mockClear();
    mockContains.mockReturnValueOnce(thenable(true));
    onAdded();

    expect(cb).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ type: "permissionrestored" }),
    );
  });

  it("triggers an error event when a required permission is removed", () => {
    mockContains.mockReturnValueOnce(thenable(true));

    const cb = vi.fn();
    permissions.addEventListener("permissionerror", cb);
    permissions.addEventListener("permissionrestored", cb);
    permissions.require("foo")(class Class {});

    expect(cb).not.toHaveBeenCalled();

    mockContains.mockReturnValueOnce(thenable(false));
    onRemoved();

    expect(cb).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ type: "permissionerror" }),
    );
  });

  it("keeps track of required and missing permissions", () => {
    // Set up classes and permissions
    class Class1 {}
    class Class2 {}
    mockContains.mockReturnValueOnce(thenable(true));
    permissions.require("webRequest")(Class1);
    mockContains.mockReturnValueOnce(thenable(false));
    permissions.require("tabs")(Class1);
    mockContains.mockReturnValueOnce(thenable(true));
    permissions.require("https://example.com/*")(Class1);
    mockContains.mockReturnValueOnce(thenable(false));
    permissions.require("notARealPermission")(Class1);
    mockContains.mockReturnValueOnce(thenable(false));
    permissions.require("scripting")(Class1);
    mockContains.mockReturnValueOnce(thenable(true));
    permissions.require("https://example.org/*")(Class2);
    expect(permissions.getRequired(Class1)).toStrictEqual(
      new Set([
        "webRequest",
        "tabs",
        "https://example.com/*",
        "notARealPermission",
        "scripting",
      ]),
    );
    expect(permissions.getRequired()).toStrictEqual(
      new Set([
        "webRequest",
        "tabs",
        "https://example.com/*",
        "notARealPermission",
        "scripting",
        "https://example.org/*",
      ]),
    );
    expect(permissions.getMissing(Class1)).toStrictEqual(
      new Set(["tabs", "notARealPermission", "scripting"]),
    );
    expect(permissions.getMissing()).toStrictEqual(
      new Set(["tabs", "notARealPermission", "scripting"]),
    );

    // Remove some permissions
    mockContains.mockImplementation(
      (p: { permissions: string[]; origins: string[] }) => {
        return thenable(
          !p.permissions.includes("tabs") &&
            !p.permissions.includes("notARealPermission") &&
            !p.permissions.includes("scripting"),
        );
      },
    );
    onRemoved();
    expect(permissions.getMissing(Class1)).toStrictEqual(
      new Set(["tabs", "notARealPermission", "scripting"]),
    );
    expect(permissions.getMissing()).toStrictEqual(
      new Set(["tabs", "notARealPermission", "scripting"]),
    );

    // Grant all permissions
    mockContains.mockReturnValue(thenable(true));
    onAdded();
    expect(permissions.getMissing(Class1)).toStrictEqual(new Set());
    expect(permissions.getMissing()).toStrictEqual(new Set());

    // Grant already granted permissions
    onAdded();
    expect(permissions.getMissing(Class1)).toStrictEqual(new Set());
    expect(permissions.getMissing()).toStrictEqual(new Set());

    // Remove some permissions
    mockContains.mockImplementation(
      (p: { permissions: string[]; origins: string[] }) => {
        return thenable(
          !p.permissions.includes("webRequest") &&
            !p.permissions.includes("scripting"),
        );
      },
    );
    onRemoved();
    expect(permissions.getMissing(Class1)).toStrictEqual(
      new Set(["webRequest", "scripting"]),
    );
    expect(permissions.getMissing()).toStrictEqual(
      new Set(["webRequest", "scripting"]),
    );
  });

  it("prints warnings to the console", () => {
    mockContains.mockReturnValueOnce(thenable(false));
    const warn = vi.spyOn(console, "warn");

    permissions.require("foo")(class Class {});

    expect(warn).toHaveBeenCalledOnce();
  });

  it("allows disabling warnings", () => {
    mockContains.mockReturnValueOnce(thenable(false));
    const warn = vi.spyOn(console, "warn");

    permissions.addEventListener("permissionerror", (event) => {
      event.preventDefault();
    });
    permissions.require("foo")(class Class {});

    expect(warn).not.toHaveBeenCalled();
  });

  it("does not trigger events when there are no requirements", () => {
    const cb = vi.fn();
    permissions.addEventListener("permissionerror", cb);
    permissions.addEventListener("permissionrestored", cb);
    permissions.check(class Class {});

    expect(cb).not.toHaveBeenCalled();
  });
});
