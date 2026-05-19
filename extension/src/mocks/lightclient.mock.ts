import {
  CryptoIndex,
  VerifyOutcome,
} from "@freedomofpress/cometbft/dist/lightclient.d";
import { SignedHeader } from "@freedomofpress/cometbft/dist/proto/cometbft/types/v1/types";
import { ValidatorSet } from "@freedomofpress/cometbft/dist/proto/cometbft/types/v1/validator";

export async function verifyCommit(
  sh: SignedHeader,
  _vset: ValidatorSet,
  _cryptoIndex: CryptoIndex,
): Promise<VerifyOutcome> {
  if (!sh?.header || !sh?.commit) {
    throw new Error("SignedHeader missing header/commit");
  }
  if (!sh.commit.blockId) throw new Error("Commit missing BlockID");
  return {
    ok: true,
    quorum: true,
    signedPower: 0n,
    totalPower: 0n,
    headerTime: sh.header.time,
    appHash: sh.header?.appHash,
    blockIdHash: sh.commit.blockId?.hash,
    unknownValidators: [],
    invalidSignatures: [],
    countedSignatures: 0,
  };
}
