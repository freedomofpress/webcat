import {
  WebcatLeaf,
  WebcatLeavesFile,
} from "@freedomofpress/ics23/dist/webcat.d";

export async function verifyWebcatProof(
  data: WebcatLeavesFile,
): Promise<readonly WebcatLeaf[] | false> {
  return data.leaves as WebcatLeaf[];
}
