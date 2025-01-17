import os
import hashlib
import json
import argparse
import glob
import subprocess
import tempfile

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

    # Ensure the directory is a folder
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a directory.")
        exit(1)

    # Scan for all matching files in the directory
    for ext in extensions:
        for file_path in glob.glob(os.path.join(directory, f'**/*{ext}'), recursive=True):
            if not os.path.isfile(file_path):
                continue  # Skip directories

            relative_path = os.path.relpath(file_path, directory).replace("\\", "/")

            if os.path.basename(file_path) in ['index.html', 'index.htm']:
                folder_path = os.path.dirname(relative_path)
                relative_path = f"/{folder_path}/" if folder_path else "/"
            else:
                relative_path = f"/{relative_path}"

            file_hash = compute_sha256(file_path)

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
        subprocess.run([
            "sigstore", "sign", "--bundle", output_bundle_path, "--overwrite", canonicalized_manifest_path
        ], check=True)
        print(f"Successfully signed {canonicalized_manifest_path} and saved the bundle to {output_bundle_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error during signing: {e}")

def collect_sigstore_bundles(bundle_paths):
    """Collects Sigstore bundles into a key-value object where the key is the identity."""
    signatures = {}
    for bundle_path in bundle_paths:
        with open(bundle_path, 'r') as f:
            bundle = json.load(f)
        signer_identity = input(f"Enter signer identity for bundle {bundle_path} (e.g., email): ")
        signatures[signer_identity] = bundle
    return signatures

def write_final_manifest(manifest, signatures, output_file):
    """Writes the final manifest including signatures."""
    final_output = {
        "manifest": manifest["manifest"],
        "signatures": signatures
    }
    with open(output_file, 'w') as f:
        json.dump(final_output, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Generate a manifest JSON for web files.")
    parser.add_argument('directory', type=str, help='Directory to scan')
    parser.add_argument('--output', type=str, required=True, help='Output final manifest JSON file with signatures')
    parser.add_argument('--app_version', type=int, default=1, help='Application version (default: 1)')
    parser.add_argument('--webcat_version', type=int, default=1, help='Webcat version (default: 1)')
    parser.add_argument('--signatures', type=int, default=1, help='Number of required Sigstore signatures (default: 1)')

    args = parser.parse_args()

    manifest = build_manifest(args.directory, args.app_version, args.webcat_version)
    manifest["manifest"]["wasm"] = prompt_additional_wasm_hashes(manifest["manifest"]["wasm"])

    canonicalized_manifest_str = canonicalize_manifest(manifest)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_manifest_file:
        canonicalized_manifest_path = temp_manifest_file.name
        temp_manifest_file.write(canonicalized_manifest_str.encode())

    bundle_paths = []
    for i in range(args.signatures):
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'_sig_{i+1}.json') as temp_bundle_file:
            output_bundle_path = temp_bundle_file.name
            sign_manifest_with_sigstore(canonicalized_manifest_path, output_bundle_path)
            bundle_paths.append(output_bundle_path)

    signatures = collect_sigstore_bundles(bundle_paths)
    write_final_manifest(manifest, signatures, args.output)

    os.remove(canonicalized_manifest_path)
    for bundle_path in bundle_paths:
        os.remove(bundle_path)

if __name__ == "__main__":
    main()
