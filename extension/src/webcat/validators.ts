import { parseContentSecurityPolicy } from "./parsers";
import { canonicalize } from '../sigstore/canonicalize'
import { SHA256 } from './utils'
import { Policy } from './interfaces';
import { bufferEqual } from '../sigstore/crypto'

export function validateCSP(csp: string) {
    // Here will go the CSP validator of the main_frame
    const res = parseContentSecurityPolicy(csp);
    return true;
}

export async function validatePolicy(policy: Policy, hash: Uint8Array) {
    // Basic functionality is lookup the policy hash (with a single issuer and identity)
    const canonicalizedPolicy = canonicalize({"signers": policy.signers, "threshold": policy.threshold});
    var calculatedHash = new Uint8Array(await SHA256(canonicalizedPolicy));
    return bufferEqual(calculatedHash, hash);
}

export async function validateManifest(manifest: Object) {
    return true;
}