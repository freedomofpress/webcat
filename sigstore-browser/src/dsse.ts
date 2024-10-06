/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
const PAE_PREFIX = 'DSSEv1';

// DSSE Pre-Authentication Encoding
export function preAuthEncoding(payloadType: string, payload: Uint8Array): Uint8Array {
  const prefix = [
    PAE_PREFIX,
    payloadType.length,
    payloadType,
    payload.length,
    '',
  ].join(' ');

  // Is using utf-8 a problem? I don't think so but adding this warning
  const encoder = new TextEncoder();
  const prefixBuffer = encoder.encode(prefix)

  // Badic Uint8Array concat
  const combinedArray = new Uint8Array(prefixBuffer.length + payload.length);

  combinedArray.set(prefixBuffer, 0);
  combinedArray.set(payload, prefixBuffer.length);
  return combinedArray;
}