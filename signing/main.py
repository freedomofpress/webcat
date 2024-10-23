import os
import hashlib
import json
import argparse
import glob
import subprocess

def compute_sha256(file_path):
    """Computes the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def build_manifest(directory, app_version, webcat_version):
    """Builds the manifest dictionary."""
    manifest = {
        "info": {
            "app_version": app_version,
            "webcat_version": webcat_version,
        },
        "files": {},
        "wasm": []
    }

    # File extensions to scan
    extensions = ['.htm', '.html', '.css', '.js', '.mjs', '.wasm']

    # Scan for all matching files in the directory
    for ext in extensions:
        for file_path in glob.glob(os.path.join(directory, f'**/*{ext}'), recursive=True):
            # Get relative path
            relative_path = os.path.relpath(file_path, directory).replace("\\", "/")
            
            # If it's index.html or index.htm, set the path to the folder path
            if os.path.basename(file_path) in ['index.html', 'index.htm']:
                relative_path = f"/{os.path.dirname(relative_path)}" if os.path.dirname(relative_path) else "/"
            else:
                relative_path = f"/{relative_path}"  # Ensure path starts with a "/"

            # Compute hash
            file_hash = compute_sha256(file_path)

            # Handle .wasm files separately
            if ext == '.wasm':
                manifest["wasm"].append(file_hash)
            else:
                manifest["files"][relative_path] = file_hash

    return {"manifest": manifest}

def prompt_additional_wasm_hashes(wasm_list):
    """Prompt the user to manually add additional WASM hashes."""
    while True:
        add_hash = input("Do you want to add another WASM hash manually? (yes/no): ").strip().lower()
        if add_hash == 'yes':
            wasm_hash = input("Enter the WASM hash: ").strip()
            if wasm_hash:
                wasm_list.append(wasm_hash)
        elif add_hash == 'no':
            break
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")
    return wasm_list

def canonicalize_manifest(manifest):
    """Canonicalizes the manifest (sorted keys, no extra whitespace) and returns it as a string."""
    return json.dumps(manifest, separators=(',', ':'), sort_keys=True)

def sign_manifest_with_sigstore(canonicalized_manifest_path, output_bundle_path):
    """Signs the canonicalized manifest using the Sigstore CLI."""
    try:
        # Run the sigstore CLI command to sign the canonicalized manifest
        subprocess.run(
            ["sigstore", "sign", "--bundle", output_bundle_path, canonicalized_manifest_path],
            check=True
        )
        print(f"Successfully signed {canonicalized_manifest_path} and saved the bundle to {output_bundle_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error during signing: {e}")

def collect_sigstore_bundles(bundle_paths):
    """Collects Sigstore bundles into a key-value object where the key is the identity."""
    signatures = {}
    for bundle_path in bundle_paths:
        with open(bundle_path, 'r') as f:
            bundle = json.load(f)
        
        # Ask for the identity of the signer (e.g., email)
        signer_identity = input(f"Enter signer identity for bundle {bundle_path} (e.g., email): ")
        
        # Use the signer identity as the key and the bundle as the value
        signatures[signer_identity] = bundle
    return signatures

def write_final_manifest(manifest, signatures, output_file):
    """Writes the final manifest including signatures."""
    final_output = {
        "manifest": manifest["manifest"],
        "signatures": signatures
    }
    # Write the final JSON to the output file
    with open(output_file, 'w') as f:
        json.dump(final_output, f, indent=4)

def write_canonicalized_manifest(canonicalized_manifest_str, canonical_output_file):
    """Writes the canonicalized manifest string to a file."""
    with open(canonical_output_file, 'w') as f:
        f.write(canonicalized_manifest_str)

def main():
    # Command line argument parsing
    parser = argparse.ArgumentParser(description="Generate a manifest JSON for web files.")
    parser.add_argument('directory', type=str, help='Directory to scan')
    parser.add_argument('--output', type=str, required=True, help='Output final manifest JSON file with signatures')
    parser.add_argument('--canonical_output', type=str, required=True, help='Output canonical manifest JSON file')
    parser.add_argument('--app_version', type=int, default=1, help='Application version (default: 1)')
    parser.add_argument('--webcat_version', type=int, default=1, help='Webcat version (default: 1)')
    parser.add_argument('--signatures', type=int, default=1, help='Number of required Sigstore signatures (default: 1)')
    parser.add_argument('--bundle_output', type=str, required=True, help='Path to save Sigstore bundles')
    
    args = parser.parse_args()

    # Build manifest
    manifest = build_manifest(args.directory, args.app_version, args.webcat_version)

    # Allow user to add more WASM hashes manually
    manifest["manifest"]["wasm"] = prompt_additional_wasm_hashes(manifest["manifest"]["wasm"])

    # Canonicalize the manifest
    canonicalized_manifest_str = canonicalize_manifest(manifest)

    # Write the canonicalized manifest to a file (this version will be signed)
    canonicalized_manifest_path = "canonicalized_manifest.json"
    write_canonicalized_manifest(canonicalized_manifest_str, canonicalized_manifest_path)

    # List to collect bundle paths
    bundle_paths = []

    # Sign the canonicalized manifest using Sigstore CLI for each required signature
    for i in range(args.signatures):
        output_bundle_path = f"{args.bundle_output}_sig_{i+1}.json"
        sign_manifest_with_sigstore(canonicalized_manifest_path, output_bundle_path)
        bundle_paths.append(output_bundle_path)

    # Collect all Sigstore bundles and their associated signer identities
    signatures = collect_sigstore_bundles(bundle_paths)

    # Write the final manifest including the manifest and the signatures
    write_final_manifest(manifest, signatures, args.output)

if __name__ == "__main__":
    main()