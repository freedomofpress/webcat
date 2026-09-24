import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.resetModules();
  vi.unstubAllGlobals();
});

describe("unwrap", () => {
  it("returns the original object when exportFunction does not exist", async () => {
    const { unwrap } = await import("../../../src/webcat/hooks/core");

    const object = {};
    expect(unwrap(object)).toBe(object);
  });

  it("calls XPCNativeWrapper.unwrap when exportFunction exists", async () => {
    const mockUnwrap = vi.fn();
    vi.stubGlobal("exportFunction", () => {});
    vi.stubGlobal("XPCNativeWrapper", { unwrap: mockUnwrap });
    const { unwrap } = await import("../../../src/webcat/hooks/core");

    const object = {};
    const unwrapped = {};
    mockUnwrap.mockReturnValueOnce(unwrapped);
    expect(unwrap(object)).toBe(unwrapped);
    expect(mockUnwrap).toHaveBeenCalledOnce();
    expect(mockUnwrap.mock.calls[0].length).toBe(1);
    expect(mockUnwrap.mock.calls[0][0]).toBe(object);
  });
});

describe("exportFunc", () => {
  it("returns the original function when exportFunction does not exist and prop is not set", async () => {
    const { exportFunc } = await import("../../../src/webcat/hooks/core");

    const func = () => {};
    const result = exportFunc(func);
    expect(result).toBe(func);
  });

  it("assigns directly to the object when exportFunction does not exist and prop is set", async () => {
    const { exportFunc } = await import("../../../src/webcat/hooks/core");

    const func = () => {};
    const object = {};
    const result = exportFunc(func, object, "prop");
    expect(result).toBe(func);
    expect(object).toStrictEqual({ prop: func });
  });

  it("returns an exported function when exportFunction exists and prop is not set", async () => {
    const mockUnwrap = vi.fn();
    const mockExportFunction = vi.fn();
    vi.stubGlobal("XPCNativeWrapper", { unwrap: mockUnwrap });
    vi.stubGlobal("exportFunction", mockExportFunction);
    const { exportFunc } = await import("../../../src/webcat/hooks/core");

    const func = () => {};
    const exported = () => {};
    const object = {};
    const unwrapped = {};
    mockUnwrap.mockReturnValueOnce(unwrapped);
    mockExportFunction.mockImplementationOnce(() => {
      return exported;
    });
    const result = exportFunc(func);
    expect(result).toBe(exported);
    expect(object).toStrictEqual({});
    expect(unwrapped).toStrictEqual({});
    expect(mockUnwrap).toHaveBeenCalledOnce();
    expect(mockUnwrap.mock.calls[0].length).toBe(1);
    expect(mockUnwrap.mock.calls[0][0]).toBe(globalThis);
    expect(mockExportFunction).toHaveBeenCalledOnce();
    expect(mockExportFunction.mock.calls[0].length).toBe(3);
    expect(mockExportFunction.mock.calls[0][0]).toBe(func);
    expect(mockExportFunction.mock.calls[0][1]).toBe(unwrapped);
    expect(mockExportFunction.mock.calls[0][2]).toStrictEqual({});
  });

  it("exports to unwrapped object when exportFunction exists and prop is set", async () => {
    const mockUnwrap = vi.fn();
    const mockExportFunction = vi.fn();
    vi.stubGlobal("XPCNativeWrapper", { unwrap: mockUnwrap });
    vi.stubGlobal("exportFunction", mockExportFunction);
    const { exportFunc } = await import("../../../src/webcat/hooks/core");

    const func = () => {};
    const exported = () => {};
    const object = {};
    const unwrapped = {};
    mockUnwrap.mockReturnValueOnce(unwrapped);
    mockExportFunction.mockImplementationOnce((_, obj, opts) => {
      obj[opts.defineAs] = exported;
      return exported;
    });
    const result = exportFunc(func, object, "prop");
    expect(result).toBe(exported);
    expect(object).toStrictEqual({});
    expect(unwrapped).toStrictEqual({ prop: exported });
    expect(mockUnwrap).toHaveBeenCalledOnce();
    expect(mockUnwrap.mock.calls[0].length).toBe(1);
    expect(mockUnwrap.mock.calls[0][0]).toBe(object);
    expect(mockExportFunction).toHaveBeenCalledOnce();
    expect(mockExportFunction.mock.calls[0].length).toBe(3);
    expect(mockExportFunction.mock.calls[0][0]).toBe(func);
    expect(mockExportFunction.mock.calls[0][1]).toBe(unwrapped);
    expect(mockExportFunction.mock.calls[0][2]).toStrictEqual({
      defineAs: "prop",
    });
  });
});

describe("makeInternal", () => {
  it("creates an unwrapped object when exportFunction exists", async () => {
    // Stub the object constructor to detect creation of fresh objects
    class FreshObject {}
    vi.stubGlobal("self", { Object: FreshObject });

    // Stub Firefox APIs
    const mockUnwrap = vi.fn();
    vi.stubGlobal("exportFunction", () => {});
    vi.stubGlobal("XPCNativeWrapper", { unwrap: mockUnwrap });

    const { makeInternal } = await import("../../../src/webcat/hooks/core");

    const unwrapped = {};
    mockUnwrap.mockReturnValueOnce(unwrapped);
    expect(makeInternal({})).toBe(unwrapped);
    expect(mockUnwrap).toHaveBeenCalledOnce();
    expect(mockUnwrap.mock.calls[0].length).toBe(1);
    expect(mockUnwrap.mock.calls[0][0]).toBeInstanceOf(FreshObject);
    expect(unwrapped).toStrictEqual({ listeners: new Map() });
  });

  it("adds all properties on the created object", async () => {
    const { makeInternal } = await import("../../../src/webcat/hooks/core");

    expect(
      makeInternal({
        foo: 1,
        bar: "lorem ipsum",
        ["dolor sit amet"]: /abc/,
      }),
    ).toStrictEqual({
      listeners: new Map(),
      foo: 1,
      bar: "lorem ipsum",
      ["dolor sit amet"]: /abc/,
    });
  });
});

describe("updatableHook", () => {
  it("runs the hook code only on first invocation", async () => {
    const { updatableHook } = await import("../../../src/webcat/hooks/core");

    const code = vi.fn();
    const scope = {} as Record<string, Record<string, { data: unknown }>>;
    updatableHook("hook", code)(scope, {});
    updatableHook("hook", code)(scope, {});
    expect(code).toHaveBeenCalledOnce();
  });

  it("resolves data as soon as it is supplied", async () => {
    const { updatableHook } = await import("../../../src/webcat/hooks/core");

    const scope = {} as Record<string, Record<string, { data: unknown }>>;
    const data = {};
    let promise: Promise<typeof data> | undefined;
    const code = vi.fn().mockImplementation((p) => {
      promise = p;
    });

    // Single call with readily available data
    updatableHook("hook1", code)(scope, data);
    expect(code).toHaveBeenCalledExactlyOnceWith(promise, scope.hooks["hook1"]);
    expect(scope.hooks["hook1"].data).toBe(data);
    await expect(promise).resolves.toBe(data);

    code.mockClear();

    // Two calls with data supplied in the second call
    updatableHook("hook2", code)(scope, "placeholder");
    expect(code).toHaveBeenCalledExactlyOnceWith(promise, scope.hooks["hook2"]);
    expect(scope.hooks["hook2"].data).toBe("placeholder");
    updatableHook("hook2", code)(scope, data);
    expect(scope.hooks["hook2"].data).toBe(data);
    await expect(promise).resolves.toBe(data);
  });
});
