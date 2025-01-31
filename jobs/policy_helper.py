import argparse
import hashlib
import json
from urllib.parse import urlparse
import requests
import struct

def compute_fqdn_hash(fqdn):
    return hashlib.sha256(fqdn.encode()).digest()

def compute_policy_hash(url):
    try:
        response = requests.get(url, verify=True)
        response.raise_for_status()

        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            raise ValueError("URL must use HTTPS.")

        if "x-sigstore-signers" not in response.headers:
            raise KeyError("Missing header: x-sigstore-signers")
        if "x-sigstore-threshold" not in response.headers:
            raise KeyError("Missing header: x-sigstore-threshold")

        signers_header = response.headers["x-sigstore-signers"]
        threshold_header = response.headers["x-sigstore-threshold"]

        signers = json.loads(signers_header)
        normalized_signers = [
            {
                "identity": signer["identity"].lower(),
                "issuer": signer["issuer"].lower()
            }
            for signer in signers
        ]
        normalized_signers.sort(key=lambda x: (x["identity"], x["issuer"]))

        policy = {
            "x-sigstore-signers": normalized_signers,
            "x-sigstore-threshold": int(threshold_header),
        }

        policy_json = json.dumps(policy, separators=(",", ":"))
        return hashlib.sha256(policy_json.encode()).digest()

    except Exception as e:
        print(f"Error generating policy hash for {url}: {e}")
        return None

def generate_source_file(hosts, output_file):
    entries = []
    for host in hosts:
        fqdn_hash = compute_fqdn_hash(host)
        policy_hash = compute_policy_hash(f"https://{host}")

        if policy_hash:
            entries.append((fqdn_hash, policy_hash))

    if output_file:
        with open(output_file, "wb") as f:
            for fqdn_hash, policy_hash in entries:
                f.write(fqdn_hash + policy_hash)

        print(f"Written {len(entries)} entries to {output_file}")

    return entries

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate FQDN and policy hashes for a list of hosts.")
    parser.add_argument("hosts", nargs="+", help="List of hosts to process.")
    parser.add_argument("--print", action="store_true", help="Print the hashes instead of writing to a file.")
    parser.add_argument("--output", help="Output file to write the raw binary data.")

    args = parser.parse_args()

    if args.print:
        for host in args.hosts:
            fqdn_hash = compute_fqdn_hash(host)
            policy_hash = compute_policy_hash(f"https://{host}")

            if policy_hash:
                print(f"Host: {host}")
                print(f"FQDN Hash: {fqdn_hash.hex()}")
                print(f"Policy Hash: {policy_hash.hex()}\n")
    elif args.output:
        generate_source_file(args.hosts, args.output)
    else:
        print("Please specify either --print or --output.")
