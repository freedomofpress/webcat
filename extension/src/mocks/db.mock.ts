export * from "../webcat/db";

import { WebcatDatabase as OriginalWebcatDatabase } from "../webcat/db";

export class WebcatDatabase extends OriginalWebcatDatabase {
  async getFQDNEnrollment(fqdn: string): Promise<Uint8Array> {
    console.log("[TESTING] getFQDNEnrollment hooked for:", fqdn);

    return new Uint8Array();
  }
}

console.log("[TESTING] Mock db module loaded");
