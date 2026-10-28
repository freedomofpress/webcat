// validateCSP.test.ts
// No browser/permissions mock: validators must load without a `browser`
// global so tooling (e.g. webcat-cli) can import them.
import { hashKey, importKey } from "@freedomofpress/sigsum/dist/crypto";
import { compilePolicy } from "@freedomofpress/sigsum/dist/policyCompiler";
import { RawPublicKey } from "@freedomofpress/sigsum/dist/types";
import { describe, expect, it, vi } from "vitest";

import {
  Uint8ArrayToBase64Url,
  Uint8ArrayToHex,
} from "../../src/webcat/encoding";
import { EnrollmentTypes, Manifest } from "../../src/webcat/interfaces/bundle";
import { WebcatErrorCode } from "../../src/webcat/interfaces/errors";
import {
  cspErrors,
  RESTRICTED_DIRECTIVES,
  validateCSP,
  validateManifest,
  verifySigsumManifest,
} from "../../src/webcat/validators";

// Mocks (unchanged)
// Signature checks are mocked; policy compilation, tree head parsing and quorum
// evaluation run for real.
vi.mock("@freedomofpress/sigsum", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@freedomofpress/sigsum")>()),
  verifyMessageWithCompiledPolicy: vi.fn(async () => true),
}));
vi.mock("@freedomofpress/sigsum/dist/crypto", async (importOriginal) => ({
  ...(await importOriginal<
    typeof import("@freedomofpress/sigsum/dist/crypto")
  >()),
  verifySignedTreeHead: vi.fn(async () => true),
  verifyCosignedTreeHead: vi.fn(async () => true),
}));
vi.mock("../../src/webcat/logger", () => ({
  logger: {
    addLog: vi.fn(),
  },
}));

describe("cspErrors", () => {
  it("reports every problem, not just the first", () => {
    expect(
      cspErrors("default-src 'none' 'self'; script-src https://cdn.example"),
    ).toEqual([
      {
        directive: "object-src",
        message: "default-src is not none, and object-src is not defined.",
      },
      {
        directive: "script-src",
        source: "https://cdn.example",
        message:
          "script-src cannot contain https://cdn.example which is unsupported.",
      },
      {
        directive: "style-src",
        message: "default-src is not none, and style-src is not defined.",
      },
      {
        directive: "worker-src",
        message: "default-src is not none, and worker-src is not defined.",
      },
    ]);
    expect(cspErrors("default-src 'none'")).toEqual([]);
    // Keywords are case-insensitive in default-src too, including the strict form.
    expect(cspErrors("default-src 'NONE'")).toEqual([]);
    expect(cspErrors("default-src 'Self'").map((e) => e.directive)).toEqual([
      "object-src",
      "script-src",
      "style-src",
      "worker-src",
    ]);
    expect(cspErrors("default-src 'none', default-src 'self'")).toEqual([
      {
        message: "CSP contains a comma: default-src 'none', default-src 'self'",
      },
    ]);
  });
});

describe("RESTRICTED_DIRECTIVES", () => {
  it("lists exactly the directives where cspErrors rejects another origin", () => {
    const rejects = (dir: string) =>
      cspErrors(
        dir === "default-src"
          ? "default-src https://x.example"
          : `default-src 'none'; ${dir} https://x.example`,
      ).some((e) => e.directive === dir && e.source);
    // The CSP directives that take a source list.
    const all = [
      "default-src",
      "script-src",
      "script-src-elem",
      "script-src-attr",
      "style-src",
      "style-src-elem",
      "style-src-attr",
      "object-src",
      "worker-src",
      "child-src",
      "frame-src",
      "img-src",
      "font-src",
      "connect-src",
      "media-src",
      "manifest-src",
      "fenced-frame-src",
      "base-uri",
      "form-action",
      "frame-ancestors",
    ];
    expect(all.filter(rejects)).toEqual(RESTRICTED_DIRECTIVES);
  });
});

describe("validateCSP", () => {
  // Test 1: Pass when default-src is 'none' (other directives are not required)
  it("should pass when default-src is 'none' even if no other directives are provided", () => {
    const csp = "default-src 'none'";
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 2: Pass with default-src 'self' and all required directives valid
  it("should pass with default-src 'self' and valid script-src, style-src, object-src, child-src/frame-src, and worker-src", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self' 'sha256-def'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 3: Missing object-src when default-src is not 'none'
  it("should throw an error if object-src is missing when default-src is not 'none'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      // object-src missing
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and object-src is not defined.",
    );
  });

  // Test 4: object-src is defined but not 'none'
  it("should throw an error if object-src is not 'none'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'sha256-abc'",
      "style-src 'self'",
      "object-src 'self'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "object-src cannot contain 'self' which is unsupported.",
    );
  });

  // Test 5: Missing script-src when default-src is not 'none'
  it("should throw an error if script-src is missing", () => {
    const csp = [
      "default-src 'self'",
      // script-src missing
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and script-src is not defined.",
    );
  });

  // Test 6: Missing style-src when default-src is not 'none'
  it("should throw an error if style-src is missing", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      // style-src missing
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and style-src is not defined.",
    );
  });

  // Test 7: Missing worker-src when default-src is not 'none'
  it("should throw an error if worker-src is missing", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      // worker-src missing
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and worker-src is not defined.",
    );
  });

  // Test 8: frame-src and child-src are not restricted
  it("does not restrict frame-src or child-src", () => {
    const base = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "worker-src 'self'",
    ];
    for (const frames of [
      [],
      ["frame-src evil.com"],
      ["child-src http://evil.com", "frame-src 'self'"],
      ["child-src 'self'", "frame-src *"],
    ]) {
      const csp = [...base, ...frames].join("; ");
      expect(validateCSP(csp)).toBeUndefined();
    }
  });

  // Test 11: style-src never allows host sources, enrolled or not
  it("should throw for any style-src host source", () => {
    for (const host of ["evil.com", "https://trusted.com"]) {
      const csp = [
        "default-src 'self'",
        "script-src 'self'",
        `style-src ${host}`,
        "object-src 'none'",
        "worker-src 'self'",
      ].join("; ");
      expect(() => validateCSP(csp)).toThrow(
        `style-src cannot contain ${host} which is unsupported`,
      );
    }
  });

  // Test 14: Valid child-src with a blob: source
  it("should pass for child-src with a blob: source", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src blob:myblob",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 16: Invalid script-src containing 'unsafe-inline'
  it("should throw an error for script-src containing 'unsafe-inline'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "script-src cannot contain 'unsafe-inline' which is unsupported.",
    );
  });

  // Test 17: Valid style-src containing 'unsafe-inline'
  it("should pass for style-src containing 'unsafe-inline'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 18: Valid script-src containing 'wasm-unsafe-eval'
  it("should pass for script-src containing 'wasm-unsafe-eval'", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 19: Valid style-src with a valid hash source
  it("should pass for style-src containing a valid hash", () => {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'sha256-validhash'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(validateCSP(csp)).toBeUndefined();
  });

  // Test 21: Blob in script-src
  it("should throw an error for a blob: in script-src", () => {
    const csp = [
      "default-src 'self'",
      "script-src blob:",
      "style-src 'self'",
      "object-src 'none'",
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");
    expect(() => validateCSP(csp)).toThrow(
      "script-src cannot contain blob: which is unsupported.",
    );
  });

  // See https://github.com/freedomofpress/webcat/issues/99
  it("should treat default-src 'none' 'self' as 'self'", () => {
    const csp = [
      "default-src 'none' 'self'",
      "script-src 'self'",
      "style-src 'self'",
      // object-src missing
      "child-src 'self'",
      "frame-src 'self'",
      "worker-src 'self'",
    ].join("; ");

    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and object-src is not defined.",
    );
  });

  // See https://github.com/freedomofpress/webcat/issues/101
  it("should throw for script-src-attr 'unsafe-inline'", () => {
    const csp =
      "default-src 'none'; script-src 'self'; style-src 'self'; script-src-attr 'unsafe-inline'";
    expect(() => validateCSP(csp)).toThrow(
      "script-src-attr cannot contain 'unsafe-inline' which is unsupported.",
    );
  });

  it("should pass for script-src-attr 'none'", () => {
    const csp =
      "default-src 'none'; script-src 'self'; style-src 'self'; script-src-attr 'none'";
    expect(validateCSP(csp)).toBeUndefined();
  });

  it("should require worker-src when child-src is set, even with default-src 'none'", () => {
    const csp = "default-src 'none'; script-src 'self'; child-src blob:";
    expect(() => validateCSP(csp)).toThrow(
      "default-src is not none, and worker-src is not defined.",
    );
  });

  it("should pass with child-src and an explicit worker-src", () => {
    const csp =
      "default-src 'none'; script-src 'self'; child-src blob:; worker-src 'self'";
    expect(validateCSP(csp)).toBeUndefined();
  });

  it("should pass when default-src 'none' 'self' has every directive", () => {
    const csp =
      "default-src 'none' 'self'; script-src 'self'; style-src 'self'; object-src 'none'; worker-src 'self'";
    expect(validateCSP(csp)).toBeUndefined();
  });

  it("should throw for malformed hash sources", () => {
    for (const hash of [
      "'sha'",
      "'sha1-AAAA'",
      "'sha256-'",
      "'sha256-not*base64'",
      "'shady'",
    ]) {
      const csp = `default-src 'none'; script-src 'self' ${hash}`;
      expect(() => validateCSP(csp)).toThrow(
        `script-src cannot contain ${hash} which is unsupported.`,
      );
    }
  });

  it("should pass for well-formed hash sources", () => {
    const csp =
      "default-src 'none'; script-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'SHA384-AAAA' 'sha512-AA_-'";
    expect(validateCSP(csp)).toBeUndefined();
  });

  it("should throw when CSP contains a comma (multiple policies)", () => {
    const csp = "script-src 'unsafe-eval', script-src 'self'";

    expect(() => validateCSP(csp)).toThrow("CSP contains a comma");
  });

  it("should throw when a valid CSP is followed by a comma and garbage", () => {
    const csp =
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "object-src 'none'",
        "worker-src 'self'",
      ].join("; ") + ", @invalid-policy";

    expect(() => validateCSP(csp)).toThrow("CSP contains a comma");
  });
});

describe("validateManifest", () => {
  const manifest: Manifest = {
    app: "app",
    version: "1.0.0",
    default_csp: "default-src 'self'",
    extra_csp: {},
    files: { "/index.html": "oUTcA3p3Jmt-YJG7Ium44fhAOOTHs-WMiJwWQH4_D8g" },
    wasm: [],
  };

  it("accepts base64url SHA-256 file hashes", () => {
    expect(validateManifest(manifest)).toBeNull();
  });

  it("accepts absent, empty and well-formed fallback_hashes, listed in files or not", () => {
    for (const fallback_hashes of [
      undefined,
      [],
      ["oUTcA3p3Jmt-YJG7Ium44fhAOOTHs-WMiJwWQH4_D8g"],
      ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    ]) {
      expect(validateManifest({ ...manifest, fallback_hashes })).toBeNull();
    }
  });

  it("rejects fallback_hashes that are not a list of base64url SHA-256 digests", () => {
    for (const fallback_hashes of [
      "oUTcA3p3Jmt-YJG7Ium44fhAOOTHs-WMiJwWQH4_D8g",
      [""],
      ["/index.html"],
      [null],
    ] as unknown as string[][]) {
      expect(validateManifest({ ...manifest, fallback_hashes })?.code).toBe(
        WebcatErrorCode.Manifest.FALLBACK_HASHES_MALFORMED,
      );
    }
  });

  it("rejects file hashes that are not base64url SHA-256 digests", () => {
    for (const hash of [
      "",
      "not base64url!",
      "a".repeat(64),
      "YQ==",
      // Non-canonical: the same digest with non-zero padding bits
      "oUTcA3p3Jmt-YJG7Ium44fhAOOTHs-WMiJwWQH4_D8h",
    ]) {
      const files = { ...manifest.files, "/x.js": hash };
      expect(validateManifest({ ...manifest, files })?.code).toBe(
        WebcatErrorCode.Manifest.FILES_MALFORMED,
      );
    }
  });
});

describe("verifySigsumManifest", () => {
  const rawKey = async () => {
    const kp = (await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    return new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  };
  const keyHashHex = async (raw: Uint8Array) =>
    Uint8ArrayToHex(
      (await hashKey(await importKey(new RawPublicKey(raw)))).bytes,
    );

  // Builds a policy with one witness per offset (quorum "any", or "none" when
  // there are no witnesses) and a cosigned tree head whose cosignature
  // timestamps are now + offset. Verifies a manifest carrying that tree head.
  const verify = async (offsets: number[], withTimestamp = true) => {
    const log = await rawKey();
    const witnesses = await Promise.all(offsets.map(rawKey));
    const names = witnesses.map((_, i) => `w${i}`);
    const policy = await compilePolicy(
      `log ${Uint8ArrayToHex(log)}\n` +
        witnesses
          .map((w, i) => `witness ${names[i]} ${Uint8ArrayToHex(w)}\n`)
          .join("") +
        (witnesses.length
          ? `group g any ${names.join(" ")}\nquorum g\n`
          : "quorum none\n"),
    );

    const now = Math.floor(Date.now() / 1000);
    const sig = "00".repeat(64);
    const treeHead = [
      "tree_size=1",
      `root_hash=${"00".repeat(32)}`,
      `signature=${sig}`,
      ...(await Promise.all(
        witnesses.map(
          async (w, i) =>
            `cosignature=${await keyHashHex(w)} ${now + offsets[i]} ${sig}`,
        ),
      )),
    ].join("\n");

    const signer = Uint8ArrayToBase64Url(await rawKey());
    const provenance: Record<string, string> = {};
    const result = await verifySigsumManifest(
      {
        type: EnrollmentTypes.Sigsum,
        signers: [signer],
        threshold: 1,
        policy: Uint8ArrayToBase64Url(policy),
        max_age: 3600,
        cas_url: "",
        logs: {},
      },
      (withTimestamp ? { timestamp: treeHead } : {}) as Manifest,
      { [signer]: "proof" },
      provenance,
    );
    if (typeof result === "number") {
      expect(provenance).toEqual({
        signed: "1",
        witnesses: String(offsets.length),
        timestamp: String(result - 3600),
      });
    }
    return { result, now };
  };

  const chosenOffset = async (offsets: number[]) => {
    const { result, now } = await verify(offsets);
    expect(typeof result).toBe("number");
    return (result as number) - 3600 - now;
  };

  it("with two cosignatures the older one wins, so one witness cannot extend validity", async () => {
    expect(await chosenOffset([-10, 100000])).toBe(-10);
  });

  it("with three cosignatures one witness can move the time in neither direction", async () => {
    expect(await chosenOffset([-100000, -10, 100000])).toBe(-10);
  });

  it("rejects a tree head with no cosignatures even when the policy needs none", async () => {
    const { result } = await verify([]);
    expect(result).toMatchObject({
      code: WebcatErrorCode.Manifest.TIMESTAMP_VERIFY_FAILED,
      details: ["no witness timestamps"],
    });
  });

  it("rejects a manifest without a timestamp", async () => {
    const { result } = await verify([-10], false);
    expect(result).toMatchObject({
      code: WebcatErrorCode.Manifest.TIMESTAMP_MISSING,
    });
  });
});
