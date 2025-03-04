# **WEBCAT Policy Hashing***

## **1. Overview**
This document defines the format and hashing mechanism for Sigstore policies, ensuring a consistent and verifiable method for encoding signer policies associated with a Fully Qualified Domain Name (FQDN).

## **2. Header Format**
Sigstore-based policies are transmitted via HTTPS headers in response to every request. The required headers are:

- **`x-sigstore-signers`** (Required): A JSON-encoded list of authorized signers.
- **`x-sigstore-threshold`** (Required): A numerical value defining the minimum number of required signers.

### **2.1 `x-sigstore-signers` Format**
The `x-sigstore-signers` header must contain a JSON array where each element is an object with the following fields:

- **`identity`** (String, Required): The signer's identity (e.g., email or OIDC identity).
- **`issuer`** (String, Required): The authority that issued the identity (e.g., Google, GitHub, etc.).

Example:
```json
[
  {
    "identity": "alice@example.com",
    "issuer": "https://accounts.google.com"
  },
  {
    "identity": "bob@example.com",
    "issuer": "https://github.com"
  }
]
```

### **2.2 `x-sigstore-threshold` Format**
The `x-sigstore-threshold` header must be an integer indicating the minimum number of signers required for policy validation.

Example:
```
x-sigstore-threshold: 2
```

### **2.3 Ensuring Headers are Unique**
It is critical to check that headers are not duplicated. If multiple instances of `x-sigstore-signers` or `x-sigstore-threshold` exist in the HTTP response, the response **must be rejected** to prevent ambiguity and potential security risks.

## **3. Policy Hashing Procedure**
The policy hash is computed in the following steps:

### **3.1 Fetch the Policy**
- A GET request is sent to the policy URL (e.g., `https://example.com`).
- The response headers are validated to ensure:
  - The URL uses HTTPS.
  - Both `x-sigstore-signers` and `x-sigstore-threshold` headers are present.
  - There are no duplicate instances of required headers.

### **3.2 Normalize Signers**
- The JSON array from `x-sigstore-signers` is parsed.
- Each signer's `identity` and `issuer` are converted to lowercase.
- The array is sorted lexicographically by (`identity`, `issuer`).

Example:
```json
[
  {
    "identity": "alice@example.com",
    "issuer": "https://accounts.google.com"
  },
  {
    "identity": "bob@example.com",
    "issuer": "https://github.com"
  }
]
```
After normalization:
```json
[
  {
    "identity": "alice@example.com",
    "issuer": "https://accounts.google.com"
  },
  {
    "identity": "bob@example.com",
    "issuer": "https://github.com"
  }
]
```

### **3.3 Construct the Policy Object**
A new JSON object is created with:
- `x-sigstore-signers`: The sorted list of normalized signers.
- `x-sigstore-threshold`: The integer value from the header.

Example:
```json
{
  "x-sigstore-signers": [
    {
      "identity": "alice@example.com",
      "issuer": "https://accounts.google.com"
    },
    {
      "identity": "bob@example.com",
      "issuer": "https://github.com"
    }
  ],
  "x-sigstore-threshold": 2
}
```

### **3.4 Serialize the Policy**
The JSON object is serialized using the following constraints:
- No extra spaces or indentation (i.e., compact representation).
- JSON keys are in their natural order.

Example serialized string:
```
{"x-sigstore-signers":[{"identity":"alice@example.com","issuer":"https://accounts.google.com"},{"identity":"bob@example.com","issuer":"https://github.com"}],"x-sigstore-threshold":2}
```

### **3.5 Compute the SHA-256 Hash**
The serialized JSON string is encoded as UTF-8 and hashed using the SHA-256 algorithm.

```
policy_hash = SHA-256(policy_json)
```

Example hash (hex encoded):
```
d2a5a67c8f5e1b43c7895b7c62a0a3b645a9643c8c7d03ec9dc8b2e2e4b5e66c
```

## **4. Verification**
To verify a policy hash:
1. Fetch the policy headers.
2. Ensure that required headers are present and unique.
3. Normalize the signers and construct the policy object.
4. Serialize the policy as JSON in compact form.
5. Compute the SHA-256 hash.
6. Compare the computed hash with the expected hash.

## **5. Supported OIDC Issuers**
The following issuers are currently supported by the community Fulcio deployment:

| Issuer Name   | URL |
|--------------|------------------------------------------------|
| Google      | `https://accounts.google.com` |
| Microsoft   | `https://login.microsoftonline.com` |
| GitHub      | `https://github.com/login/oauth` |

In the case of a dedicated Fulcio deployment instead of the community one, it would be possible to add any number of identity providers as needed.

---

This process ensures that Sigstore policies are consistently formatted and hashed in a reproducible manner, allowing for reliable verification and integrity checks.
