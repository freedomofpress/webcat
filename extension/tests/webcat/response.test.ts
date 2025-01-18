import { beforeEach, describe, expect, it, vi } from "vitest";

import { Sigstore } from "../../src/sigstore/interfaces";
import {
  Issuers,
  OriginState,
  PopupState,
} from "./../../src/webcat/interfaces";
import { validateResponseHeaders } from "./../../src/webcat/response";

vi.stubGlobal(
  "fetch",
  vi.fn(() =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve({
          info: { app_version: 1, webcat_version: 1 },
          files: {},
          wasm: [],
        }),
    }),
  ),
);

vi.mock("./../../src/webcat/logger", () => ({
  logger: {
    addLog: vi.fn(),
  },
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

async function generatePolicyHash(responseHeadersArray) {
  // Convert the array of headers into a key-value map
  const responseHeaders = responseHeadersArray.reduce((acc, header) => {
    acc[header.name.toLowerCase()] = header.value;
    return acc;
  }, {});

  const normalizedSigners = JSON.parse(responseHeaders["x-sigstore-signers"])
    .map((signer) => ({
      identity: signer.identity.toLowerCase(),
      issuer: signer.issuer.toLowerCase(),
    }))
    .sort(
      (a, b) =>
        a.identity.localeCompare(b.identity) ||
        a.issuer.localeCompare(b.issuer),
    );

  const cspRules = responseHeaders["content-security-policy"]
    .split(";")
    .map((rule) => rule.trim().toLowerCase())
    .filter((rule) => rule.length > 0)
    .sort();

  const normalizedCsp = cspRules.join("; ");

  const policyObject = {
    "x-sigstore-signers": normalizedSigners,
    "x-sigstore-threshold": parseInt(
      responseHeaders["x-sigstore-threshold"],
      10,
    ),
    "content-security-policy": normalizedCsp,
  };

  const policyString = JSON.stringify(policyObject);
  const encoder = new TextEncoder();
  const data = encoder.encode(policyString);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

describe("validateResponseHeaders", () => {
  let originState: OriginState;
  let popupState: PopupState;
  let details: browser.webRequest._OnHeadersReceivedDetails;

  const defaultCSP = "script-src 'self'; style-src 'self'; object-src 'none'";
  const defaultThreshold = 2;
  const defaultSigners = `[{"identity": "demo@web.cat", "issuer": "${Issuers.google}"}, {"identity": "test@example.com", "issuer": "${Issuers.microsoft}"}, {"identity": "identity@domain.com", "issuer": "${Issuers.github}"}]`;

  beforeEach(() => {
    originState = new OriginState("example.com");
    popupState = new PopupState("example.com", 1);
    details = {
      url: "https://example.com",
      tabId: 1,
      responseHeaders: [
        {
          name: "Content-Security-Policy",
          value: defaultCSP,
        },
        {
          name: "X-Sigstore-Signers",
          value: defaultSigners,
        },
        { name: "X-Sigstore-Threshold", value: `${defaultThreshold}` },
      ],
    } as unknown as browser.webRequest._OnHeadersReceivedDetails;
  });

  it("validates correct headers successfully", async () => {
    originState.policyHash = await generatePolicyHash(details.responseHeaders);
    await expect(
      validateResponseHeaders({} as Sigstore, originState, popupState, details),
    ).resolves.not.toThrow();
    expect(popupState.valid_headers).toBe(true);
  });

  it("throws error when response headers are missing", async () => {
    originState.policyHash = await generatePolicyHash(details.responseHeaders);
    details.responseHeaders = undefined;
    await expect(
      validateResponseHeaders({} as Sigstore, originState, popupState, details),
    ).rejects.toThrow("Missing response headers.");
  });

  it("throws error for duplicate critical headers", async () => {
    originState.policyHash = await generatePolicyHash(details.responseHeaders);
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    details.responseHeaders!.push({
      name: "X-Sigstore-Threshold",
      value: `${defaultThreshold}`,
    });
    await expect(
      validateResponseHeaders({} as Sigstore, originState, popupState, details),
    ).rejects.toThrow(
      "Duplicate critical header detected: x-sigstore-threshold",
    );
  });

  it("throws error for invalid signers json", async () => {
    originState.policyHash = await generatePolicyHash(details.responseHeaders);
    details.responseHeaders = [
      { name: "Content-Security-Policy", value: defaultCSP },
      { name: "X-Sigstore-Signers", value: `invalid` },
      { name: "X-Sigstore-Threshold", value: `${defaultThreshold}` },
    ];
    await expect(
      validateResponseHeaders({} as Sigstore, originState, popupState, details),
    ).rejects.toThrow("Error parsing JSON in x-sigstore-signers SyntaxError:");
  });
  it("throws error for threshold > signers", async () => {
    details.responseHeaders = [
      { name: "Content-Security-Policy", value: defaultCSP },
      {
        name: "X-Sigstore-Signers",
        value: defaultSigners,
      },
      { name: "X-Sigstore-Threshold", value: "5" },
    ];
    originState.policyHash = await generatePolicyHash(details.responseHeaders);
    await expect(
      validateResponseHeaders({} as Sigstore, originState, popupState, details),
    ).rejects.toThrow(
      "Signing threshold is greater than the number of possible signers.",
    );
  });

  // TODO enable this test. ValidateCSP is tested separately, but this test serve the purpose of ensuring it's being called
  // at the right moment. I can't get it to work because I fail at doing a partial mock of the validators module
  /*it("throws error if CSP validation fails with non non allowed CSP", async () => {
    details.responseHeaders = [
      {
        name: "Content-Security-Policy",
        value:
          "script-src 'none' 'unsafe-inline'; style-src 'self'; object-src 'none'",
      },
      {
        name: "X-Sigstore-Signers", value: defaultSigners
      },
      { name: "X-Sigstore-Threshold", value: `${defaultThreshold}` },
    ];
    originState.policyHash = await generatePolicyHash(details.responseHeaders);

    await expect(
      validateResponseHeaders({} as Sigstore, originState, popupState, details),
    ).rejects.toThrow("CSP provided by the server has non allowed directives!");
  });*/

  it("throws error for mismatched Sigstore signers header", async () => {
    originState.policyHash = await generatePolicyHash(details.responseHeaders);

    details.responseHeaders = [
      {
        name: "Content-Security-Policy",
        value: defaultCSP,
      },
      {
        name: "X-Sigstore-Signers",
        value: `[{"identity": "eve@evil.cat", "issuer": "${Issuers.google}"}, {"identity": "eve2@evil.cat", "issuer": "${Issuers.google}"}]`,
      },
      { name: "X-Sigstore-Threshold", value: `${defaultThreshold}` },
    ];

    await expect(
      validateResponseHeaders({} as Sigstore, originState, popupState, details),
    ).rejects.toThrow("Response headers do not match the preload list.");
  });

  it("throws error for mismatched CSP header", async () => {
    details.responseHeaders = [
      {
        name: "Content-Security-Policy",
        value: "script-src 'self'; style-src: 'self'; object-src 'none",
      },
      { name: "X-Sigstore-Signers", value: defaultSigners },
      { name: "X-Sigstore-Threshold", value: `${defaultThreshold}` },
    ];
    await expect(
      validateResponseHeaders({} as Sigstore, originState, popupState, details),
    ).rejects.toThrow("Response headers do not match the preload list.");
  });
});
