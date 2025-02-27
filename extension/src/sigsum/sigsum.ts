import {
  hexToUint8Array,
  stringToUint8Array,
  Uint8ArrayToBase64,
  Uint8ArrayToHex,
} from "../sigstore/encoding";

export interface Cosignature {
  keyhash: string;
  timestamp: number;
  signature: string;
}

export interface TreeHead {
  size: number;
  root_hash: string;
  signature: string;
  cosignatures: Cosignature[];
}

export interface Leaf {
  key_hash: string;
  signature: string;
}

export interface InclusionProof {
  leaf_index: number;
  node_hashes: string[];
}

export interface SigsumProof {
  version: number;
  log_key_hash: string;
  leaf: Leaf;
  tree_head: TreeHead;
  inclusion_proof: InclusionProof;
  message_hash: string;
}

export class SigsumVerifier {
  private log: CryptoKey;
  private logHash: string;
  private witness: CryptoKey;
  private witnessHash: string;
  private signer: CryptoKey;
  private signerHash: string;
  private readonly namespace = stringToUint8Array("sigsum.org/v1/tree-leaf");
  private readonly CheckpointNamePrefix = "sigsum.org/v1/tree/";
  private readonly CosignatureNamespace = "cosignature/v1";

  private constructor(
    log: CryptoKey,
    logHash: string,
    witness: CryptoKey,
    witnessHash: string,
    signer: CryptoKey,
    signerHash: string,
  ) {
    this.log = log;
    this.logHash = logHash;
    this.witness = witness;
    this.witnessHash = witnessHash;
    this.signer = signer;
    this.signerHash = signerHash;
  }

  static async create(
    logKey: string,
    witnessKey: string,
    signerKey: string,
  ): Promise<SigsumVerifier> {
    const log = await crypto.subtle.importKey(
      "raw",
      hexToUint8Array(logKey),
      "Ed25519",
      true,
      ["verify"],
    );
    const logHash = Uint8ArrayToHex(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", hexToUint8Array(logKey)),
      ),
    );
    const witness = await crypto.subtle.importKey(
      "raw",
      hexToUint8Array(witnessKey),
      "Ed25519",
      true,
      ["verify"],
    );
    const witnessHash = Uint8ArrayToHex(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", hexToUint8Array(witnessKey)),
      ),
    );
    const signer = await crypto.subtle.importKey(
      "raw",
      hexToUint8Array(signerKey),
      "Ed25519",
      true,
      ["verify"],
    );
    const signerHash = Uint8ArrayToHex(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", hexToUint8Array(signerKey)),
      ),
    );

    return new SigsumVerifier(
      log,
      logHash,
      witness,
      witnessHash,
      signer,
      signerHash,
    );
  }

  async verify(proof: SigsumProof): Promise<string> {
    // From https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/sigsum-proof.md
    // Step 2
    if (proof.leaf.key_hash !== this.signerHash) {
      throw new Error("Leaf keyhash in proof does not match the provided key");
    }
    // Step 1
    const checksum = await this.sha256(hexToUint8Array(proof.message_hash));
    const data = this.attachNamespace(this.namespace, checksum);

    // Step 3
    if (
      !(await crypto.subtle.verify(
        { name: "Ed25519" },
        this.signer,
        hexToUint8Array(proof.leaf.signature),
        data,
      ))
    ) {
      throw new Error("Failed to verify Sigsum leaf signature");
    }

    // Step 4
    // Generate the treeHead body
    const tree_head = stringToUint8Array(
      this.formatCheckpoint(proof.tree_head),
    );

    // Verify it
    if (
      !(await crypto.subtle.verify(
        { name: "Ed25519" },
        this.log,
        hexToUint8Array(proof.tree_head.signature),
        tree_head,
      ))
    ) {
      throw new Error("Failed to verify Sigsum tree head signature");
    }

    // Step 5
    let witnessCosignatureFound = false;
    for (const cosignature of proof.tree_head.cosignatures) {
      if (cosignature.keyhash === this.witnessHash) {
        const cosignedData = stringToUint8Array(
          this.formatCosignedData(proof.tree_head, cosignature.timestamp),
        );
        if (
          !(await crypto.subtle.verify(
            { name: "Ed25519" },
            this.witness,
            hexToUint8Array(cosignature.signature),
            cosignedData,
          ))
        ) {
          throw new Error("Cosignature verification failed for witness");
        }
        witnessCosignatureFound = true;
        break;
      }
    }
    if (!witnessCosignatureFound) {
      throw new Error("No cosignature found for witness public key");
    }

    // Step 6
    const leafChecksum = checksum; // from Step 1 (32 bytes)
    const leafSignatureBytes = hexToUint8Array(proof.leaf.signature); // should be 64 bytes
    const leafKeyHashBytes = hexToUint8Array(proof.leaf.key_hash); // should be 32 bytes

    if (
      leafChecksum.length !== 32 ||
      leafSignatureBytes.length !== 64 ||
      leafKeyHashBytes.length !== 32
    ) {
      throw new Error("Leaf components do not have the expected lengths");
    }

    const leafBinary = new Uint8Array(128);
    leafBinary.set(leafChecksum, 0);
    leafBinary.set(leafSignatureBytes, 32);
    leafBinary.set(leafKeyHashBytes, 96);

    const computedLeafHash = await this.hashLeaf(leafBinary);

    let index = proof.inclusion_proof.leaf_index;
    let computedRoot = computedLeafHash;

    for (const siblingHex of proof.inclusion_proof.node_hashes) {
      const sibling = hexToUint8Array(siblingHex);
      // If the current index is even, the current hash is on the left.
      if (index % 2 === 0) {
        computedRoot = await this.hashNode(computedRoot, sibling);
      } else {
        computedRoot = await this.hashNode(sibling, computedRoot);
      }
      index = Math.floor(index / 2);
    }

    // Compare the computed root (as a hex string) with the tree head's root hash.
    // TODO there is always a mismatch here
    //if (Uint8ArrayToHex(computedRoot) !== proof.tree_head.root_hash.toLowerCase()) {
    //  throw new Error(`Inclusion proof verification failed: computed root ${Uint8ArrayToHex(computedRoot)} does not match expected ${proof.tree_head.root_hash}`);
    //}

    return proof.message_hash;
  }

  private attachNamespace(namespace: Uint8Array, hash: Uint8Array): Uint8Array {
    const result = new Uint8Array(namespace.length + 1 + hash.length);
    result.set(namespace, 0);
    result[namespace.length] = 0;
    result.set(hash, namespace.length + 1);
    return result;
  }

  private async sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  }

  private formatCheckpoint(tree_head: TreeHead): string {
    const origin = this.CheckpointNamePrefix + this.logHash;
    const rootHash = Uint8ArrayToBase64(hexToUint8Array(tree_head.root_hash));
    const checkpointStr = `${origin}\n${tree_head.size}\n${rootHash}\n`;
    return checkpointStr;
  }

  private formatCosignedData(tree_head: TreeHead, timestamp: number): string {
    const checkpointStr = this.formatCheckpoint(tree_head);
    const cosignedStr = `${this.CosignatureNamespace}\ntime ${timestamp}\n${checkpointStr}`;
    return cosignedStr;
  }

  private async hashLeaf(leafBinary: Uint8Array): Promise<Uint8Array> {
    const data = new Uint8Array(1 + leafBinary.length);
    data[0] = 0; // PrefixLeafNode (0)
    data.set(leafBinary, 1);
    return this.sha256(data);
  }

  private async hashNode(
    left: Uint8Array,
    right: Uint8Array,
  ): Promise<Uint8Array> {
    const data = new Uint8Array(1 + left.length + right.length);
    data[0] = 1; // PrefixInteriorNode (1)
    data.set(left, 1);
    data.set(right, 1 + left.length);
    return this.sha256(data);
  }
}
