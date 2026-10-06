#!/usr/bin/env python3
"""
ulp-driver: patch signature policy verifier (userspace pre-flight check)
Supports:
  1. Sigstore cosign (ECDSA-P256 blob signatures)
  2. OpenPGP / GPG (detached signatures)
Post-quantum signing is not implemented yet (see TODO.md).
"""

import sys
import os
import json
import base64
import hashlib
import tempfile
import subprocess

POLICY_PATH = "/etc/ulp/policy.json"
if not os.path.exists(POLICY_PATH):
    POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ulp-keys", "policy.json")

def load_policy(policy_file=None):
    if policy_file is None:
        policy_file = POLICY_PATH
    if not os.path.exists(policy_file):
        raise FileNotFoundError(f"Policy file not found at {policy_file}")
    with open(policy_file, "r") as f:
        return json.load(f)

def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def verify_cosign(payload_path, sig_path, key_path):
    if not os.path.exists(sig_path):
        return False, f"Signature file missing: {sig_path}"
    if not os.path.exists(key_path):
        return False, f"Public key missing: {key_path}"

    cmd = [
        "cosign", "verify-blob",
        "--key", key_path,
        "--signature", sig_path,
        "--insecure-ignore-tlog=true",
        payload_path
    ]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            return True, "Cosign/Sigstore ECDSA signature verified successfully"
        else:
            return False, f"Cosign verification failed: {res.stderr.strip()}"
    except FileNotFoundError:
        return False, "cosign binary not installed on system"

def verify_gpg(payload_path, sig_path, key_path):
    if not os.path.exists(sig_path):
        return False, f"GPG signature missing: {sig_path}"
    if not os.path.exists(key_path):
        return False, f"GPG keyring missing: {key_path}"

    cmd = [
        "gpg", "--no-default-keyring",
        "--keyring", key_path,
        "--verify", sig_path, payload_path
    ]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            return True, "GPG OpenPGP signature verified successfully"
        else:
            return False, f"GPG verification failed: {res.stderr.strip()}"
    except FileNotFoundError:
        return False, "gpg binary not installed on system"

def verify_patch(binary_target, payload_path, sig_path=None):
    policy = load_policy()
    transports = policy.get("transports", {}).get("livepatch", {})
    rules = transports.get(binary_target)

    if not rules:
        default_policy = policy.get("default", [{"type": "reject"}])
        for p in default_policy:
            if p.get("type") == "insecureAcceptAnything":
                return True, "Accepted under insecureAcceptAnything default rule", compute_sha256(payload_path)
        return False, f"Target binary '{binary_target}' has no matching policy and default is reject", None

    errors = []
    for req in rules:
        req_type = req.get("type")
        key_path = req.get("keyPath")

        # Adjust local path if needed for testing
        if key_path and not os.path.exists(key_path):
            local_key = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ulp-keys", os.path.basename(key_path))
            if os.path.exists(local_key):
                key_path = local_key

        if req_type in ("pqcSigned", "hybridSigned"):
            errors.append(f"{req_type} (not implemented: post-quantum signing was removed, see TODO.md)")

        elif req_type == "sigstoreSigned":
            auto_sig = sig_path or f"{payload_path}.cosign.sig"
            ok, msg = verify_cosign(payload_path, auto_sig, key_path)
            if ok:
                return True, f"[{binary_target}] {msg}", compute_sha256(payload_path)
            errors.append(f"sigstoreSigned ({msg})")

        elif req_type == "signedBy":
            auto_sig = sig_path or f"{payload_path}.sig"
            ok, msg = verify_gpg(payload_path, auto_sig, key_path)
            if ok:
                return True, f"[{binary_target}] {msg}", compute_sha256(payload_path)
            errors.append(f"signedBy ({msg})")

        elif req_type == "insecureAcceptAnything":
            return True, f"[{binary_target}] Allowed by insecureAcceptAnything", compute_sha256(payload_path)
        else:
            errors.append(f"Unknown policy type '{req_type}'")

    return False, f"[{binary_target}] Signature verification failed for all configured policy rules: {'; '.join(errors)}", None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <binary_target> <payload_path> [signature_path]")
        sys.exit(1)

    target_bin = sys.argv[1]
    payload = sys.argv[2]
    sig = sys.argv[3] if len(sys.argv) > 3 else None

    valid, reason, digest = verify_patch(target_bin, payload, sig)
    if valid:
        print(f"[ULP-POLICY: PASS] {reason}")
        print(f"  SHA-256 Digest: {digest}")
        sys.exit(0)
    else:
        print(f"[ULP-POLICY: REJECT] {reason}", file=sys.stderr)
        sys.exit(1)
