#!/usr/bin/env python3
"""
ulp-driver: Enterprise Cryptographic Patch Policy Verifier
Supports:
  1. Post-Quantum Cryptography (NIST FIPS 204 ML-DSA-65 / CRYSTALS-Dilithium)
  2. Hybrid Dual-Layer Attestation (Classical ECDSA via Cosign + Post-Quantum ML-DSA-65)
  3. Sigstore Cosign (ECDSA-P256 OCI/Blob Attestation)
  4. OpenPGP / GPG (Detached signatures)
"""

import sys
import os
import json
import base64
import hashlib
import tempfile
import subprocess
from ulp_pqc_signer import MLDSA65

POLICY_PATH = "/etc/ulp/policy.json"
if not os.path.exists(POLICY_PATH):
    POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.json")

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

def verify_pqc_mldsa(payload_path, sig_path, key_path):
    if not os.path.exists(sig_path):
        return False, f"PQC signature file missing: {sig_path}"
    if not os.path.exists(key_path):
        return False, f"PQC public key missing: {key_path}"

    try:
        with open(payload_path, "rb") as f:
            payload_bytes = f.read()
        with open(key_path, "r") as f:
            key_data = json.load(f)
        with open(sig_path, "r") as f:
            sig_data = json.load(f)

        pk = base64.b64decode(key_data["public_key_b64"])
        sig = base64.b64decode(sig_data["signature_b64"])

        # Check payload digest matches signature commitment
        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
        if sig_data.get("payload_sha256") and sig_data["payload_sha256"] != payload_sha256:
            return False, f"PQC payload SHA256 mismatch (expected {sig_data['payload_sha256']}, got {payload_sha256})"

        ok = MLDSA65.verify(pk, payload_bytes, sig)
        if ok:
            return True, "NIST FIPS 204 ML-DSA-65 (Post-Quantum 128-bit) signature verified successfully"
        else:
            return False, "ML-DSA-65 cryptographic signature verification failed"
    except Exception as e:
        return False, f"PQC verification error: {str(e)}"

def verify_hybrid(payload_path, sig_path, pqc_key_path, classical_key_path):
    if not os.path.exists(sig_path):
        return False, f"Hybrid signature missing: {sig_path}"
    if not os.path.exists(pqc_key_path):
        return False, f"PQC public key missing: {pqc_key_path}"
    if not os.path.exists(classical_key_path):
        return False, f"Classical public key missing: {classical_key_path}"

    tmp_file = None
    try:
        with open(payload_path, "rb") as f:
            payload_bytes = f.read()
        with open(sig_path, "r") as f:
            hybrid_data = json.load(f)

        # 1. Verify Post-Quantum ML-DSA Layer
        with open(pqc_key_path, "r") as f:
            pqc_key_data = json.load(f)
        pk = base64.b64decode(pqc_key_data["public_key_b64"])
        pqc_sig = base64.b64decode(hybrid_data["post_quantum"]["signature_b64"])

        ok_pqc = MLDSA65.verify(pk, payload_bytes, pqc_sig)
        if not ok_pqc:
            return False, "Hybrid verification failed at Post-Quantum (ML-DSA-65) layer"

        # 2. Verify Classical Layer (Cosign or GPG)
        classical_sig_str = hybrid_data["classical"]["signature_b64"]
        with tempfile.NamedTemporaryFile(prefix="ulp_hybrid_", suffix=".sig", delete=False) as tf:
            tf.write(classical_sig_str.encode("utf-8"))
            tmp_file = tf.name

        if "cosign" in classical_key_path or "sigstore" in hybrid_data["classical"].get("provider", "").lower():
            ok_c, msg_c = verify_cosign(payload_path, tmp_file, classical_key_path)
        else:
            ok_c, msg_c = verify_gpg(payload_path, tmp_file, classical_key_path)

        if not ok_c:
            return False, f"Hybrid verification failed at Classical layer: {msg_c}"

        return True, "Dual-Layer Hybrid (Classical ECDSA + Post-Quantum ML-DSA-65) verified successfully"
    except Exception as e:
        return False, f"Hybrid verification error: {str(e)}"
    finally:
        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass

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
            local_key = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ulp-keys", os.path.basename(key_path))
            if os.path.exists(local_key):
                key_path = local_key

        if req_type == "pqcSigned":
            auto_sig = sig_path or f"{payload_path}.pqc.sig"
            ok, msg = verify_pqc_mldsa(payload_path, auto_sig, key_path)
            if ok:
                return True, f"[{binary_target}] {msg}", compute_sha256(payload_path)
            errors.append(f"pqcSigned ({msg})")

        elif req_type == "hybridSigned":
            pqc_key = req.get("pqcKeyPath")
            classical_key = req.get("classicalKeyPath")
            if pqc_key and not os.path.exists(pqc_key):
                pqc_key = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ulp-keys", os.path.basename(pqc_key))
            if classical_key and not os.path.exists(classical_key):
                classical_key = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ulp-keys", os.path.basename(classical_key))

            auto_sig = sig_path or f"{payload_path}.hybrid.sig"
            ok, msg = verify_hybrid(payload_path, auto_sig, pqc_key, classical_key)
            if ok:
                return True, f"[{binary_target}] {msg}", compute_sha256(payload_path)
            errors.append(f"hybridSigned ({msg})")

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
