import os
import json
import hashlib
import pytest
import tempfile
import subprocess
from unittest.mock import patch, mock_open
from signer import (
    compute_sha256, load_config, build_manifest, canonicalize_manifest,
    sign_manifest_with_sigstore, collect_sigstore_bundles, write_final_manifest
)

def test_compute_sha256():
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test data")
        temp_file_path = temp_file.name
    
    expected_hash = hashlib.sha256(b"test data").hexdigest()
    assert compute_sha256(temp_file_path) == expected_hash
    os.remove(temp_file_path)

def test_load_config_valid():
    config_data = {
        "app_name": "TestApp",
        "app_version": "1.0",
        "default_csp": "default-src 'self'",
        "extra_csp": {}
    }
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = os.path.join(temp_dir, "webcat.config.json")
        with open(config_path, "w") as f:
            json.dump(config_data, f)
        config = load_config(temp_dir)
        assert config == config_data

def test_load_config_missing_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        with pytest.raises(ValueError, match="does not exist"):
            load_config(temp_dir)

def test_load_config_missing_fields():
    invalid_config = {"app_name": "TestApp"}
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = os.path.join(temp_dir, "webcat.config.json")
        with open(config_path, "w") as f:
            json.dump(invalid_config, f)
        with pytest.raises(ValueError, match="Missing required field"): 
            load_config(temp_dir)

def test_build_manifest():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file_path = os.path.join(temp_dir, "index.html")
        with open(test_file_path, "w") as f:
            f.write("<html></html>")
        config = {"app_name": "TestApp", "app_version": "1.0", "default_csp": "default-src 'self'"}
        manifest = build_manifest(temp_dir, config)
        assert "/" in manifest["manifest"]["files"]

def test_canonicalize_manifest():
    manifest = {"b": 2, "a": 1}
    expected = json.dumps({"a": 1, "b": 2}, separators=(',', ':'), sort_keys=True)
    assert canonicalize_manifest(manifest) == expected

@patch("subprocess.run")
def test_sign_manifest_with_sigstore(mock_run):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        sign_manifest_with_sigstore(temp_file.name, "output.json")
    mock_run.assert_called_once()
    os.remove(temp_file.name)

@patch("builtins.input", side_effect=["test@example.com"])
def test_collect_sigstore_bundles(mock_input):
    bundle_data = {"signed": True}
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_file:
        json.dump(bundle_data, temp_file)
        temp_file_path = temp_file.name
    
    signatures = collect_sigstore_bundles([temp_file_path])
    assert "test@example.com" in signatures
    assert signatures["test@example.com"] == bundle_data
    os.remove(temp_file_path)

def test_write_final_manifest():
    manifest = {"manifest": {"files": {"/index.html": "abc123"}}}
    signatures = {"test@example.com": {"signed": True}}
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        output_path = temp_file.name
    
    write_final_manifest(manifest, signatures, output_path)
    
    with open(output_path, 'r') as f:
        result = json.load(f)
    assert result["manifest"] == manifest["manifest"]
    assert result["signatures"] == signatures
    os.remove(output_path)

