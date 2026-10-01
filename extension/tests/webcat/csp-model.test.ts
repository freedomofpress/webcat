// Model check of validateCSP against CSP3 semantics.
// See https://github.com/freedomofpress/webcat/issues/83
//
// Generated policies run through the real validateCSP. For each accepted
// policy, an independent CSP3 model computes the browser-effective source
// list per execution vector and compares it with WEBCAT's allow-list. A
// failure prints the accepted policy and what becomes effective.
//
// Pass 1: every single-token assignment of the directives in a fallback group.
// Pass 2: mutations of accepted policies (extra tokens, duplicate directives,
// case, whitespace).
import { describe, expect, it } from "vitest";

import { validateCSP } from "../../src/webcat/validators";

// ---------------------------------------------------------------------------
// CSP3 model. Independent of src/webcat/parsers.ts: parser bugs must show
// up here.

// https://w3c.github.io/webappsec-csp/#parse-serialized-policy
// ASCII whitespace only; tokens with non-ASCII code points are skipped.
const ASCII_WS = /^[\t\n\f\r ]+|[\t\n\f\r ]+$/g;
function parse(policy: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const raw of policy.split(";")) {
    const token = raw.replace(ASCII_WS, "");
    if (!token || !/^[\x00-\x7f]*$/.test(token)) continue;
    const [name, ...value] = token.split(/[\t\n\f\r ]+/);
    const lower = name.toLowerCase();
    if (out.has(lower)) continue; // first directive wins
    out.set(lower, value);
  }
  return out;
}

// Fallback chains, most specific first.
// https://w3c.github.io/webappsec-csp/#directive-fallback-list
const FALLBACK: Record<string, string[]> = {
  "script-src-elem": ["script-src-elem", "script-src", "default-src"],
  "script-src-attr": ["script-src-attr", "script-src", "default-src"],
  "style-src-elem": ["style-src-elem", "style-src", "default-src"],
  "style-src-attr": ["style-src-attr", "style-src", "default-src"],
  "object-src": ["object-src", "default-src"],
  "worker-src": ["worker-src", "child-src", "script-src", "default-src"],
};

// No directive in the chain: no restriction, '*'. Empty value: 'none'.
// Keywords are ASCII case-insensitive.
function effective(parsed: Map<string, string[]>, vector: string): string[] {
  for (const d of FALLBACK[vector]) {
    const list = parsed.get(d);
    if (list !== undefined)
      return list.length ? list.map((t) => t.toLowerCase()) : ["'none'"];
  }
  return ["*"];
}

// WEBCAT allow-list per vector, applied to the effective list. Browsers
// ignore 'none' next to other sources and invalid tokens; only tokens outside
// the set matter.
//
// Known exception, not modelled: a CSP3 hash source also matches an external
// <script src> or stylesheet whose integrity attribute carries the same
// digest. A hash in script-src allows a byte-pinned script from any origin.
// Integrity holds; the origin promise does not.
const HASH = "'sha256-aaaa'";
const SCRIPT_OK = new Set(["'none'", "'self'", "'wasm-unsafe-eval'", HASH]);
const STYLE_OK = new Set([
  "'none'",
  "'self'",
  "'unsafe-inline'",
  "'unsafe-hashes'",
  HASH,
]);
const ALLOWED: Record<string, Set<string>> = {
  "script-src-elem": SCRIPT_OK,
  "script-src-attr": SCRIPT_OK,
  "style-src-elem": STYLE_OK,
  "style-src-attr": STYLE_OK,
  "object-src": new Set(["'none'"]),
  "worker-src": new Set(["'none'", "'self'", "'wasm-unsafe-eval'", HASH]),
};

// Stricter sets for directives written out explicitly, matching the
// validator exactly so that relaxing it fails here. Inherited values are
// covered by ALLOWED.
const DIRECT: Record<string, Set<string>> = {
  "script-src-attr": new Set(["'none'"]),
  "worker-src": new Set(["'none'", "'self'"]),
  "object-src": new Set(["'none'"]),
};

function check(csp: string): string[] {
  const parsed = parse(csp);
  const problems: string[] = [];
  for (const vector in ALLOWED) {
    const bad = effective(parsed, vector).filter(
      (t) => !ALLOWED[vector].has(t),
    );
    if (bad.length) problems.push(`${vector} -> ${bad.join(" ")}`);
  }
  for (const directive in DIRECT) {
    const own = parsed.get(directive) ?? [];
    const bad = own.filter((t) => !DIRECT[directive].has(t.toLowerCase()));
    if (bad.length)
      problems.push(`${directive} (explicit) -> ${bad.join(" ")}`);
  }
  return problems;
}

function accepts(csp: string): boolean {
  try {
    validateCSP(csp);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Generation

// One token per source kind. validateCSP treats a kind uniformly: keyword
// equality, 'sha prefix, everything else rejected.
const TOKENS = [
  "'none'",
  "'self'",
  "'unsafe-inline'",
  "'unsafe-eval'",
  "'unsafe-hashes'",
  "'strict-dynamic'",
  "'wasm-unsafe-eval'",
  "'sha256-AAAA'",
  "'nonce-AAAA'",
  "blob:",
  "https://evil.example",
];
const DEFAULT_SRC = ["", "'none'", "'self'", "'none' 'self'"];

type Result = { accepted: string[]; failures: string[] };

function record(csp: string, r: Result) {
  if (!accepts(csp)) return;
  r.accepted.push(csp);
  const problems = check(csp);
  if (problems.length && r.failures.length < 10)
    r.failures.push(`${csp}\n    ${problems.join("\n    ")}`);
}

// Pass 1: default-src x (absent | one token) for each directive in `group`;
// `filler` supplies valid values for the directives outside the group.
function enumerate(group: string[], filler: string): Result {
  const options = ["", ...TOKENS];
  const r: Result = { accepted: [], failures: [] };
  const idx = new Array(group.length).fill(0);
  for (const def of DEFAULT_SRC) {
    idx.fill(0);
    for (;;) {
      const parts = [def && `default-src ${def}`, filler];
      group.forEach((d, i) => idx[i] && parts.push(`${d} ${options[idx[i]]}`));
      record(parts.filter(Boolean).join("; "), r);
      let i = 0;
      while (i < idx.length && ++idx[i] === options.length) idx[i++] = 0;
      if (i === idx.length) break;
    }
  }
  return r;
}

// Deterministic PRNG (mulberry32) so failures reproduce.
function rng(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T>(rand: () => number, xs: T[]) =>
  xs[Math.floor(rand() * xs.length)];

const DIRECTIVES = [
  "default-src",
  ...Object.keys(FALLBACK),
  "script-src",
  "style-src",
  "child-src",
];

function flipCase(s: string, rand: () => number) {
  return s.replace(/[a-z]/g, (c) => (rand() < 0.5 ? c.toUpperCase() : c));
}

// Pass 2: mutate an accepted policy. Each case covers what pass 1 cannot.
function mutate(csp: string, rand: () => number): string {
  const parts = csp.split("; ");
  const i = Math.floor(rand() * parts.length);
  switch (Math.floor(rand() * 6)) {
    case 0: // extra token on an existing directive
      parts[i] += ` ${pick(rand, TOKENS)}`;
      break;
    case 1: // duplicate directive appended: browser ignores it
      parts.push(`${parts[i].split(" ")[0]} ${pick(rand, TOKENS)}`);
      break;
    case 2: // duplicate directive prepended: browser uses it instead
      parts.unshift(`${parts[i].split(" ")[0]} ${pick(rand, TOKENS)}`);
      break;
    case 3: // a directive absent from the policy
      parts.push(`${pick(rand, DIRECTIVES)} ${pick(rand, TOKENS)}`);
      break;
    case 4: // case changes in names and keywords
      parts[i] = flipCase(parts[i], rand);
      break;
    default: // whitespace
      parts[i] = parts[i].replace(/ /g, () =>
        pick(rand, [" ", "  ", "\t", " \t "]),
      );
  }
  return parts.join(pick(rand, ["; ", ";", " ; ", ";  "]));
}

function fuzz(seeds: string[], n: number, seed: number): Result {
  const rand = rng(seed);
  const r: Result = { accepted: [], failures: [] };
  for (let k = 0; k < n; k++) {
    let csp = pick(rand, seeds);
    const rounds = 1 + Math.floor(rand() * 3);
    for (let j = 0; j < rounds; j++) csp = mutate(csp, rand);
    record(csp, r);
  }
  return r;
}

// ---------------------------------------------------------------------------

const GROUPS: [string, string[], string][] = [
  [
    "script",
    [
      "script-src",
      "script-src-elem",
      "script-src-attr",
      "child-src",
      "worker-src",
    ],
    "style-src 'self'; object-src 'none'",
  ],
  [
    "style",
    ["style-src", "style-src-elem", "style-src-attr"],
    "script-src 'self'; object-src 'none'; worker-src 'self'",
  ],
  [
    "object",
    ["object-src"],
    "script-src 'self'; style-src 'self'; worker-src 'self'",
  ],
];

describe("validateCSP against a CSP3 model", () => {
  for (const [name, group, filler] of GROUPS) {
    it(`${name} group: exhaustive single-token, then mutated`, () => {
      const pass1 = enumerate(group, filler);
      expect(pass1.accepted.length).toBeGreaterThan(1);
      expect(pass1.failures, pass1.failures.join("\n\n")).toEqual([]);

      const pass2 = fuzz(pass1.accepted, 20000, 83);
      expect(pass2.accepted.length).toBeGreaterThan(1000);
      expect(pass2.failures, pass2.failures.join("\n\n")).toEqual([]);
    }, 60000);
  }

  it("the model itself flags the known bypasses", () => {
    expect(
      check(
        "default-src 'none'; script-src 'self'; script-src-attr 'unsafe-inline'",
      ),
    ).not.toEqual([]);
    expect(
      check("default-src 'none'; script-src 'self'; child-src blob:"),
    ).not.toEqual([]);
    expect(check("default-src 'self'; script-src 'self'")).not.toEqual([]); // object-src falls to 'self'
    expect(check("script-src blob:; script-src 'self'")).not.toEqual([]); // first wins
    expect(
      check("default-src 'none'; script-src 'self'; script-src-attr 'self'"),
    ).not.toEqual([]); // explicit attr must be 'none'
    expect(
      check("default-src 'none'; script-src 'self'; worker-src 'sha256-AAAA'"),
    ).not.toEqual([]); // explicit worker-src
    expect(
      check(
        "SCRIPT-SRC 'SELF'; object-src 'none'; style-src 'self'; worker-src 'self'",
      ),
    ).toEqual([]);
    expect(
      check(
        "default-src 'none'; script-src 'self' 'sha256-AAAA'; style-src 'self' 'unsafe-inline'",
      ),
    ).toEqual([]);
  });
});
