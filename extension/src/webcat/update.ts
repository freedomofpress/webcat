import { importCommit } from "@freedomofpress/cometbft/dist/commit";
import { verifyCommit } from "@freedomofpress/cometbft/dist/lightclient";
import { CommitJson, ValidatorJson } from "@freedomofpress/cometbft/dist/types";
import { importValidators } from "@freedomofpress/cometbft/dist/validators";
import {
  verifyWebcatProof,
  WebcatLeavesFile,
} from "@freedomofpress/ics23/dist/webcat";

import { WebcatDatabase } from "./db";
import { hexToUint8Array, Uint8ArrayToBase64 } from "./encoding";
import { arraysEqual } from "./utils";

declare const __TESTING__: boolean;

export async function update(
  db: WebcatDatabase,
  endpoint: string,
): Promise<void> {
  if (__TESTING__) {
    console.log("[webcat] Running test list updater");
    db.setLastChecked();
    // updateDatabase has also a __TESTING__ condition; later we might want to move everything into the same place
    //await updateDatabase(db, "", 1337, new Uint8Array());
  } else {
    // Running update procedure from webcat-infra-chain
    // Steps:
    // 1. Load validatorSet from disk (must be bundled with the extension for now, we could support validatorSet updates in the future)
    // 2. Fetch latest block
    // 3. Verify block against validatorSet
    // 4. Check block date is > than last update block date
    // 5. Fetch leaves file
    // 6. Verify leaves file app_hash matches the block one
    // 7. Verify leaves against app_hash (leaf by leaf)
    // 8. Update local database

    // 1 TODO SECURITY: load validatorSet from disk
    console.log("[webcat] Running production list updater");

    // 2 Fetch latest block
    const blockResponse = await fetch(`${endpoint}block.json`, {
      cache: "no-store",
    });
    const block = await blockResponse.json();
    console.log("[webcat] Update block fetched");
    // 3 Verify block against validatorSet
    const { proto: vset, cryptoIndex } = await importValidators(
      block.validator_set as ValidatorJson,
    );
    const sh = importCommit(block as CommitJson);
    const out = await verifyCommit(sh, vset, cryptoIndex);

    if (out.ok) {
      console.log(
        "[webcat] Block verified, app_hash: ",
        Uint8ArrayToBase64(out.appHash),
        "time: ",
        out.headerTime,
      );
    } else {
      throw new Error(`Block verification failed: ${out}`);
    }

    if (!out.headerTime) {
      throw new Error("Block verification did not return a time");
    }
    const lastBlockTime = await db.getLastBlockTime();
    if (lastBlockTime !== null && out.headerTime.seconds <= lastBlockTime) {
      throw new Error("Block time is not newer than the last update");
    }

    // 5 Fetch leaves file
    const leavesResponse = await fetch(`${endpoint}leaves.json`, {
      cache: "no-store",
    });
    const leaves = (await leavesResponse.json()) as WebcatLeavesFile;

    // 6 Verify leaves file app_hash matches the block one
    if (!arraysEqual(hexToUint8Array(leaves.proof.app_hash), out.appHash)) {
      throw new Error("app hash mismatch");
    }

    // TODO: split canonical root hash verification and leaves verification in different steps
    // So that we update the leaves only if the root hash is new. Then we can update lastchecked and lastblocktime only

    // 7 Verify leaves against the canonical_root_hash and app_hash
    const verifiedLeaves = await verifyWebcatProof(leaves);

    if (verifiedLeaves === false) {
      throw new Error("proof did not verify against app hash");
    }

    await db.setLastChecked();
    await db.updateList(verifiedLeaves);
    await db.setLastBlockTime(out.headerTime?.seconds);
    await db.setRootHash(leaves.proof.canonical_root_hash);

    console.log(`[webcat] List updated successfully`);
  }
}
