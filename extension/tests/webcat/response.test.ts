import { beforeEach, describe, expect, it, vi } from "vitest";

import { SigstoreVerifier } from "../../src/sigstore/sigstore";
import {
  OriginStateBase,
  OriginStateHolder,
  OriginStateInitial,
  OriginStateVerifiedEnrollment,
  OriginStateVerifiedManifest,
} from "../../src/webcat/interfaces/originstate";
import { PopupState } from "../../src/webcat/interfaces/popupstate";
import { Issuers } from "./../../src/webcat/interfaces/base";
import { validateResponseHeaders } from "./../../src/webcat/response";

// Define a mutable version of the origin state for testing purposes.
interface MutableOriginState extends OriginStateBase {
  manifest: unknown;
  manifest_data: unknown;
  policy_hash: Uint8Array;
}

vi.mock("./../../dist/hooks.js?raw", () => {
  return { default: "" };
});

vi.stubGlobal(
  "fetch",
  vi.fn(() =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve({
          manifest: {
            app_name: "testapp",
            app_version: "1.0",
            comment: "",
            files: {},
            wasm: [],
            // Use proper CSP syntax (no colon/commas)
            default_csp:
              "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'",
            extra_csp: {},
          },
          signatures: {
            demo1: {},
            demo2: {},
          },
        }),
    }),
  ),
);

vi.mock("./../../src/webcat/logger", () => ({
  logger: { addLog: vi.fn() },
}));

vi.mock("./../../src/webcat/ui", () => ({
  setIcon: vi.fn(),
  setOKIcon: vi.fn(),
  setErrorIcon: vi.fn(),
}));

vi.mock("../../src/webcat/validators", () => ({
  validateCSP: vi.fn(async () => true),
  validateManifest: vi.fn(async () => true),
}));

async function generatePolicyHash(
  responseHeadersArray: Array<{ name: string; value: string }>,
) {
  // Convert the array of headers into a key-value map.
  const responseHeaders = responseHeadersArray.reduce(
    (acc: Record<string, string>, header) => {
      acc[header.name.toLowerCase()] = header.value;
      return acc;
    },
    {},
  );

  const normalizedSigners = JSON.parse(responseHeaders["x-sigstore-signers"])
    .map((signer: { identity: string; issuer: string }) => ({
      identity: signer.identity.toLowerCase(),
      issuer: signer.issuer.toLowerCase(),
    }))
    .sort(
      (a, b) =>
        a.identity.localeCompare(b.identity) ||
        a.issuer.localeCompare(b.issuer),
    );

  const policyObject = {
    "x-sigstore-signers": normalizedSigners,
    "x-sigstore-threshold": parseInt(
      responseHeaders["x-sigstore-threshold"],
      10,
    ),
  };

  const policyString = JSON.stringify(policyObject);
  const encoder = new TextEncoder();
  const data = encoder.encode(policyString);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

describe("validateResponseHeaders", () => {
  let originStateHolder: OriginStateHolder;
  let popupState: PopupState;
  let details: browser.webRequest._OnHeadersReceivedDetails;

  const defaultCSP =
    "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'";
  const defaultThreshold = 2;
  const defaultSigners = `[{"identity": "demo@web.cat", "issuer": "${Issuers.google}"}, {"identity": "test@example.com", "issuer": "${Issuers.microsoft}"}, {"identity": "identity@domain.com", "issuer": "${Issuers.github}"}]`;

  beforeEach(async () => {
    originStateHolder = new OriginStateHolder(
      new OriginStateInitial(
        {} as SigstoreVerifier,
        "example.com",
        new Uint8Array([0]),
      ),
    );
    const manifestResponse = await originStateHolder.current.manifestPromise;
    // Cast current state to MutableOriginState so we can assign mutable properties.
    const mutableState = originStateHolder.current as MutableOriginState;
    mutableState.manifest = await manifestResponse.json();

    // Create a dummy manifest that meets validation requirements.
    const dummyManifest = {
      app_name: "testapp",
      app_version: "1.0",
      comment: "",
      files: { "index.html": "dummy content" },
      wasm: [],
      default_csp: defaultCSP,
      extra_csp: {},
    };

    // Set manifest_data and manifest.
    mutableState.manifest_data = {
      manifest: dummyManifest,
      signatures: { demo1: {}, demo2: {} },
    };
    mutableState.manifest = dummyManifest;

    // Bypass signature validation by stubbing verifyManifest.
    vi.spyOn(
      OriginStatePopulatedManifest.prototype,
      "verifyManifest",
    ).mockResolvedValue(
      new OriginStateVerifiedManifest(
        mutableState,
        dummyManifest,
        [
          { identity: "demo@web.cat", issuer: Issuers.google },
          { identity: "test@example.com", issuer: Issuers.microsoft },
        ],
        new Set(["example.com"]),
      ),
    );

    // Instantiate PopupState with the required parameters.
    popupState = new PopupState("example.com", 1, 1, 42, 0, "1.0");
    details = {
      url: "https://example.com",
      tabId: 1,
      responseHeaders: [
        { name: "Content-Security-Policy", value: defaultCSP },
        { name: "X-Sigstore-Signers", value: defaultSigners },
        { name: "X-Sigstore-Threshold", value: `${defaultThreshold}` },
      ],
    } as unknown as browser.webRequest._OnHeadersReceivedDetails;
  });

  it("validates correct headers successfully", async () => {
    const mutableState = originStateHolder.current as MutableOriginState;
    mutableState.policy_hash = await generatePolicyHash(
      details.responseHeaders,
    );
    await expect(
      validateResponseHeaders(originStateHolder, popupState, details),
    ).resolves.not.toThrow();
    expect(popupState.valid_headers).toBe(true);
  });

  it("throws error when response headers are missing", async () => {
    const mutableState = originStateHolder.current as MutableOriginState;
    mutableState.policy_hash = await generatePolicyHash(
      details.responseHeaders,
    );
    // Simulate missing headers with an empty array.
    details.responseHeaders = [];
    await expect(
      validateResponseHeaders(originStateHolder, popupState, details),
    ).rejects.toThrow(
      "Error parsing headers: Error: Missing critical header: content-security-policy",
    );
  });

  it("throws error for duplicate critical headers", async () => {
    const mutableState = originStateHolder.current as MutableOriginState;
    mutableState.policy_hash = await generatePolicyHash(
      details.responseHeaders,
    );
    // Add a duplicate X-Sigstore-Threshold header.
    details.responseHeaders.push({
      name: "X-Sigstore-Threshold",
      value: `${defaultThreshold}`,
    });
    await expect(
      validateResponseHeaders(originStateHolder, popupState, details),
    ).rejects.toThrow(
      "Duplicate critical header detected: x-sigstore-threshold",
    );
  });

  it("throws error for invalid signers json", async () => {
    const mutableState = originStateHolder.current as MutableOriginState;
    mutableState.policy_hash = await generatePolicyHash(
      details.responseHeaders,
    );
    details.responseHeaders = [
      { name: "Content-Security-Policy", value: defaultCSP },
      { name: "X-Sigstore-Signers", value: "invalid" },
      { name: "X-Sigstore-Threshold", value: `${defaultThreshold}` },
    ];
    await expect(
      validateResponseHeaders(originStateHolder, popupState, details),
    ).rejects.toThrow("Error parsing JSON in x-sigstore-signers SyntaxError:");
  });

  it("throws error for threshold > signers", async () => {
    details.responseHeaders = [
      { name: "Content-Security-Policy", value: defaultCSP },
      { name: "X-Sigstore-Signers", value: defaultSigners },
      { name: "X-Sigstore-Threshold", value: "5" },
    ];
    const mutableState = originStateHolder.current as MutableOriginState;
    mutableState.policy_hash = await generatePolicyHash(
      details.responseHeaders,
    );
    await expect(
      validateResponseHeaders(originStateHolder, popupState, details),
    ).rejects.toThrow(
      "Signing threshold is greater than the number of possible signers.",
    );
  });

  it("throws error for mismatched Sigstore signers header", async () => {
    const mutableState = originStateHolder.current as MutableOriginState;
    mutableState.policy_hash = await generatePolicyHash(
      details.responseHeaders,
    );
    details.responseHeaders = [
      { name: "Content-Security-Policy", value: defaultCSP },
      {
        name: "X-Sigstore-Signers",
        value: `[{"identity": "eve@evil.cat", "issuer": "${Issuers.google}"}, {"identity": "eve2@evil.cat", "issuer": "${Issuers.google}"}]`,
      },
      { name: "X-Sigstore-Threshold", value: `${defaultThreshold}` },
    ];
    await expect(
      validateResponseHeaders(originStateHolder, popupState, details),
    ).rejects.toThrow(
      "Error validating headers: response headers do not match the preload list.",
    );
  });

  it("throws error for mismatched CSP header", async () => {
    const mutableState = originStateHolder.current as MutableOriginState;
    mutableState.policy_hash = await generatePolicyHash(
      details.responseHeaders,
    );
    // Provide a CSP header that does not match the dummy manifest default_csp.
    details.responseHeaders = [
      {
        name: "Content-Security-Policy",
        value:
          "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'",
      },
      { name: "X-Sigstore-Signers", value: defaultSigners },
      { name: "X-Sigstore-Threshold", value: `${defaultThreshold}` },
    ];
    await expect(
      validateResponseHeaders(originStateHolder, popupState, details),
    ).rejects.toThrow("Failed to match CSP with manifest value for /");
  });
});
