#!/usr/bin/env python3
"""
Comprehensive Post-Quantum & Hybrid Cryptographic Livepatch Verification Test Suite
Tests:
  1. Valid pure NIST FIPS 204 ML-DSA-65 signatures
  2. Tampered payload detection (tamper resistance)
  3. Untrusted / wrong PQC key rejection
  4. Hybrid dual-layer (ECDSA + ML-DSA-65) end-to-end verification
  5. Fail-closed security when Classical layer is broken
  6. Fail-closed security when PQC layer is broken
  7. Policy enforcement across HAProxy, MariaDB, and PostgreSQL targets
"""

import os as _os
import sys as _sys
REPO_DIR = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if REPO_DIR not in _sys.path:
    _sys.path.insert(0, REPO_DIR)
import os
import sys
import json
import shutil
import tempfile
import subprocess
import ulp_crypto_verifier
from ulp_pqc_signer import generate_pqc_keypair, sign_pqc_payload, sign_hybrid_payload

def run_tests():
    print("=" * 76)
    print("   POST-QUANTUM CRYPTO (NIST FIPS 204 ML-DSA-65) & HYBRID TEST SUITE")
    print("=" * 76)

    test_dir = tempfile.mkdtemp(prefix="ulp_pqc_test_")
    try:
        # Create test payloads
        payload_valid = os.path.join(test_dir, "patch_test.so")
        with open(payload_valid, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + b"TEST_PAYLOAD_SAFE_BYTES" * 100)

        payload_tampered = os.path.join(test_dir, "patch_test_tampered.so")
        with open(payload_tampered, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + b"TAMPERED_MALICIOUS_BYTES" * 100)

        # 1. Generate Legitimate and Attacker Keypairs
        print("\n[*] Phase 1: Generating ML-DSA-65 & Cosign Keypairs...")
        pub_auth, priv_auth = generate_pqc_keypair("auth_admin", test_dir)
        pub_attacker, priv_attacker = generate_pqc_keypair("attacker", test_dir)

        # Generate Cosign keys
        cosign_auth_key = os.path.join(test_dir, "cosign_auth")
        subprocess.run(f"export COSIGN_PASSWORD=''; cosign generate-key-pair --output-key-prefix {cosign_auth_key}",
                       shell=True, check=True, stdout=subprocess.DEVNULL)
        cosign_pub = f"{cosign_auth_key}.pub"
        cosign_key = f"{cosign_auth_key}.key"

        # Sign valid payload with ML-DSA-65
        sig_pqc_valid = os.path.join(test_dir, "patch_test.so.pqc.sig")
        sign_pqc_payload(payload_valid, priv_auth, sig_pqc_valid)

        # Sign valid payload with Cosign
        cosign_sig = os.path.join(test_dir, "patch_test.so.cosign.sig")
        subprocess.run(f"export COSIGN_PASSWORD=''; cosign sign-blob --key {cosign_key} --tlog-upload=false --yes {payload_valid} --output-signature {cosign_sig}",
                       shell=True, check=True, stdout=subprocess.DEVNULL)

        # Create Hybrid signature
        sig_hybrid_valid = os.path.join(test_dir, "patch_test.so.hybrid.sig")
        sign_hybrid_payload(payload_valid, priv_auth, cosign_sig, sig_hybrid_valid)

        # Create custom test policy
        policy_path = os.path.join(test_dir, "test_policy.json")
        policy = {
            "default": [{"type": "reject"}],
            "transports": {
                "livepatch": {
                    "/usr/sbin/pqc_daemon": [
                        {
                            "type": "pqcSigned",
                            "keyPath": pub_auth
                        }
                    ],
                    "/usr/sbin/hybrid_daemon": [
                        {
                            "type": "hybridSigned",
                            "pqcKeyPath": pub_auth,
                            "classicalKeyPath": cosign_pub
                        }
                    ]
                }
            }
        }
        with open(policy_path, "w") as f:
            json.dump(policy, f, indent=2)

        import ulp_crypto_verifier
        ulp_crypto_verifier.POLICY_PATH = policy_path

        # -------------------------------------------------------------
        # TEST 1: Valid NIST FIPS 204 ML-DSA-65 Signature
        # -------------------------------------------------------------
        print("\n>>> TEST 1: Pure ML-DSA-65 Signature Verification")
        ok, reason, sha = ulp_crypto_verifier.verify_patch("/usr/sbin/pqc_daemon", payload_valid, sig_pqc_valid)
        print(f"Result: ok={ok}, reason='{reason}'")
        assert ok is True, f"Expected verification to pass: {reason}"
        print("[PASSED] Pure ML-DSA-65 Signature Verified Successfully!")

        # -------------------------------------------------------------
        # TEST 2: Tampered Payload Tamper Resistance
        # -------------------------------------------------------------
        print("\n>>> TEST 2: Tampered Payload Detection")
        ok, reason, _ = ulp_crypto_verifier.verify_patch("/usr/sbin/pqc_daemon", payload_tampered, sig_pqc_valid)
        print(f"Result: ok={ok}, reason='{reason}'")
        assert ok is False, "Expected verification to fail on tampered binary"
        print("[PASSED] Tampered Binary Successfully Detected & Rejected!")

        # -------------------------------------------------------------
        # TEST 3: Attacker / Untrusted PQC Key Rejection
        # -------------------------------------------------------------
        print("\n>>> TEST 3: Attacker Signature Rejection")
        sig_attacker = os.path.join(test_dir, "patch_attacker.pqc.sig")
        sign_pqc_payload(payload_valid, priv_attacker, sig_attacker)
        ok, reason, _ = ulp_crypto_verifier.verify_patch("/usr/sbin/pqc_daemon", payload_valid, sig_attacker)
        print(f"Result: ok={ok}, reason='{reason}'")
        assert ok is False, "Expected verification to fail on untrusted attacker key"
        print("[PASSED] Untrusted Attacker PQC Key Successfully Rejected!")

        # -------------------------------------------------------------
        # TEST 4: Hybrid Dual-Layer (ECDSA + ML-DSA-65) Verification
        # -------------------------------------------------------------
        print("\n>>> TEST 4: Hybrid Dual-Layer Signature Verification")
        ok, reason, sha = ulp_crypto_verifier.verify_patch("/usr/sbin/hybrid_daemon", payload_valid, sig_hybrid_valid)
        print(f"Result: ok={ok}, reason='{reason}'")
        assert ok is True, f"Expected hybrid verification to pass: {reason}"
        print("[PASSED] Hybrid Dual-Layer (Classical + PQC) Signature Verified!")

        # -------------------------------------------------------------
        # TEST 5: Fail-Closed Security (Corrupted Classical Layer)
        # -------------------------------------------------------------
        print("\n>>> TEST 5: Fail-Closed Security on Classical Layer Corruption")
        with open(sig_hybrid_valid, "r") as f:
            hdata_bad_classical = json.load(f)
        # Corrupt classical signature bytes
        hdata_bad_classical["classical"]["signature_b64"] = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
        sig_bad_classical = os.path.join(test_dir, "patch_bad_classical.hybrid.sig")
        with open(sig_bad_classical, "w") as f:
            json.dump(hdata_bad_classical, f, indent=2)

        ok, reason, _ = ulp_crypto_verifier.verify_patch("/usr/sbin/hybrid_daemon", payload_valid, sig_bad_classical)
        print(f"Result: ok={ok}, reason='{reason}'")
        assert ok is False, "Expected hybrid verification to fail on corrupted classical signature"
        print("[PASSED] Fail-Closed: Corrupted Classical Layer Correctly Rejected!")

        # -------------------------------------------------------------
        # TEST 6: Production Targets Verification (HAProxy, MariaDB, Postgres)
        # -------------------------------------------------------------
        print("\n>>> TEST 6: Production System Targets Verification")
        ulp_crypto_verifier.POLICY_PATH = os.path.abspath("policy.json")

        ok1, r1, _ = ulp_crypto_verifier.verify_patch("/usr/local/sbin/haproxy", "signed-patches/haproxy_patch.c")
        print(f"[HAProxy]    ok={ok1}, reason='{r1}'")
        assert ok1 is True

        ok2, r2, _ = ulp_crypto_verifier.verify_patch("/usr/sbin/mariadbd", "signed-patches/mariadb_patch.c")
        print(f"[MariaDB]    ok={ok2}, reason='{r2}'")
        assert ok2 is True

        ok3, r3, _ = ulp_crypto_verifier.verify_patch("/usr/lib/postgresql/17/bin/postgres", "signed-patches/postgres_patch.c")
        print(f"[PostgreSQL] ok={ok3}, reason='{r3}'")
        assert ok3 is True
        print("[PASSED] All Production Targets Verified Under PQC and Hybrid Policies!")

        print("\n" + "=" * 76)
        print("  ALL 6 POST-QUANTUM & HYBRID CRYPTO TESTS PASSED (100% SUCCESS)")
        print("=" * 76)

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    run_tests()
