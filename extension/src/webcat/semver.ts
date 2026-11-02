/**
 * Splits a version into its numeric core and prerelease identifiers. Any
 * leading "v" is tolerated (drawio ships "v31.1.8") and build metadata after
 * "+" is ignored, as Semantic Versioning 2.0.0 section 10 requires.
 */
function parse(version: string): [number[], string[]] {
  const [core, prerelease = ""] = version
    .replace(/^v+/i, "")
    .split("+")[0]
    .split(/-(.*)/s);
  return [core.split(".").map(Number), prerelease ? prerelease.split(".") : []];
}

/**
 * Whether `a` has higher precedence than `b` under Semantic Versioning 2.0.0
 * section 11.
 */
export function isNewerSemver(a: string, b: string): boolean {
  const [coreA, preA] = parse(a);
  const [coreB, preB] = parse(b);

  for (let i = 0; i < Math.max(coreA.length, coreB.length); i++) {
    const diff = (coreA[i] ?? 0) - (coreB[i] ?? 0);
    if (diff) return diff > 0;
  }

  if (preA.length === 0 || preB.length === 0) {
    return preA.length === 0 && preB.length > 0;
  }

  for (let i = 0; i < Math.min(preA.length, preB.length); i++) {
    const [x, y] = [preA[i], preB[i]];
    const [numX, numY] = [/^\d+$/.test(x), /^\d+$/.test(y)];
    if (numX && numY) {
      if (Number(x) !== Number(y)) return Number(x) > Number(y);
    } else if (numX !== numY) {
      return numY;
    } else if (x !== y) {
      return x > y;
    }
  }
  return preA.length > preB.length;
}
