# Quick ChatGPT helper for debugging policies manually
import argparse
import hashlib
import json
import requests
from urllib.parse import urlparse

def check_tls_and_headers(url):
    try:
        # Validate URL and perform GET request
        response = requests.get(url, verify=True)
        response.raise_for_status()

        # Ensure HTTPS is used
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            raise ValueError("URL must use HTTPS.")

        # Extract and validate headers
        if "x-sigstore-signers" not in response.headers:
            raise KeyError("Missing header: x-sigstore-signers")
        if "x-sigstore-threshold" not in response.headers:
            raise KeyError("Missing header: x-sigstore-threshold")
        if "content-security-policy" not in response.headers:
            raise KeyError("Missing header: content-security-policy")

        # Extract headers
        signers_header = response.headers["x-sigstore-signers"]
        threshold_header = response.headers["x-sigstore-threshold"]
        csp_header = response.headers["content-security-policy"]

        # Normalize x-sigstore-signers
        signers = json.loads(signers_header)
        normalized_signers = []
        for signer in signers:
            # Normalize the keys by ensuring 'identity' comes before 'issuer'
            keys = sorted(signer.keys())
            if keys != ["identity", "issuer"]:
                raise ValueError(f"Unexpected keys in signer: {keys}")

            normalized_signer = {
                "identity": signer["identity"].lower(),
                "issuer": signer["issuer"].lower()
            }
            normalized_signers.append(normalized_signer)

        # Sort normalized signers by identity and issuer
        sorted_signers = sorted(normalized_signers, key=lambda x: (x["identity"], x["issuer"]))

        # Normalize CSP
        csp_rules = [rule.strip().lower() for rule in csp_header.split(";") if rule.strip()]
        csp_rules.sort()
        normalized_csp = "; ".join(csp_rules)

        # Combine policy and compute hash
        policy = {
            "x-sigstore-signers": sorted_signers,
            "x-sigstore-threshold": int(threshold_header),
            "content-security-policy": normalized_csp
        }
        policy_json = json.dumps(policy, separators=(",", ":"))
        policy_hash = hashlib.sha256(policy_json.encode()).hexdigest()

        print(f"Policy Hash: {policy_hash}")
        return policy_hash

    except KeyError as e:
        raise Exception(f"Header validation error: {e}")
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check URL for TLS and generate policy hash.")
    parser.add_argument("url", help="URL to check")
    args = parser.parse_args()

    try:
        check_tls_and_headers(args.url)
    except Exception as e:
        print(f"Error: {e}")