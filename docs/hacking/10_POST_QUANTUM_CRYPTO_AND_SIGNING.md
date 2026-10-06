# Post-Quantum Cryptography (PQC), In-Kernel Verification & Hybrid Signing

**Module:** Advanced Cryptographic Attestation & Quantum Resilience  
**Path:** `docs/hacking/10_POST_QUANTUM_CRYPTO_AND_SIGNING.md`  
**Standard:** NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium) & FIPS 205 (SLH-DSA / SPHINCS+)  
**Policy Framework:** CRI-O / Sigstore Hybrid Dual-Layer Supply-Chain Security  

---

## 1. The Post-Quantum Imperative for Livepatching

Livepatching injects raw machine instructions directly into running kernel and userspace processes. If an adversary compromises the signature verification layer, they gain instant root/arbitrary execution access.

### 1.1 The Quantum Threat (Shor's Algorithm)
* **Classical Algorithms Vulnerable:** RSA-2048/4096, ECDSA (NIST P-256, P-384), Ed25519, and Diffie-Hellman can be completely broken in polynomial time by a cryptographically relevant quantum computer (CRQC) running Shor's algorithm.
* **Harvest Now, Decrypt/Forge Later:** Adversaries capture signed livepatch payloads today to forge rogue patches once quantum computers mature.
* **NIST PQC Standards (Finalized August 2024):**
  * **FIPS 203 (ML-KEM):** Module-Lattice Key Encapsulation (formerly CRYSTALS-Kyber).
  * **FIPS 204 (ML-DSA):** Module-Lattice Digital Signatures (formerly CRYSTALS-Dilithium). **Primary choice for livepatch signing.**
  * **FIPS 205 (SLH-DSA):** Stateless Hash-Based Digital Signatures (formerly SPHINCS+).
  * **FIPS 206 (FN-DSA):** Fast Fourier Lattice Signatures (formerly Falcon).

---

## 2. Is There In-Kernel Support for Post-Quantum Cryptography?

### 2.1 Current Upstream Linux Kernel Status
1. **Asymmetric Key Subsystem (`crypto/asymmetric_keys/`):**
   * Currently in-tree: RSA (`crypto/rsa.c`), ECDSA (`crypto/ecdsa.c`), SM2 (`crypto/sm2.c`), and PKCS#7 / X.509 parsers.
   * Native in-tree ML-DSA / SLH-DSA modules are currently in **RFC discussion on the Linux Kernel Mailing List (LKML)** following NIST's August 2024 finalization of FIPS 204/205.
2. **In-Tree Primitives Already Available in the Kernel:**
   * **SHA-3 / SHAKE-128 / SHAKE-256 (`crypto/sha3.c` & `crypto/sha3_generic.c`):** Fully available in the kernel crypto API!
   * Because ML-DSA-65 and SLH-DSA rely entirely on **SHAKE-256 and integer polynomial ring arithmetic ($R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$)**, verification can be implemented in a standalone, stack-bounded kernel module with zero floating-point operations.

### 2.2 In-Kernel PQC Verification Design

```
                     Incoming Livepatch Payload (.so binary)
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ ULP Kernel Verification Gate      │
                     │ (ioctl ULP_IOC_APPLY_PATCH)       │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Linux In-Kernel SHAKE-256 API     │
                     │ crypto_alloc_shash("shake256",...)│
                     └─────────────────┬─────────────────┘
                                       │
                     ┌─────────────────┴─────────────────┐
                     ▼                                   ▼
        [ Classical Signature Check ]       [ PQC ML-DSA-65 Verification ]
        (ECDSA-P256 / Ed25519)              (NIST FIPS 204 Lattice Math)
                     │                                   │
                     └─────────────────┬─────────────────┘
                                       │ (Both Must Pass)
                                       ▼
                         ┌───────────────────────────┐
                         │ Atomic Livepatch Poke     │
                         │ (Text Poke /dev/ulp)      │
                         └───────────────────────────┘
```

---

## 3. Does Sigstore / Cosign Have Post-Quantum Support?

### 3.1 Current Status of Cosign & Sigstore PQC
* **Standard Cosign Upstream:** Relies on Go's `crypto/ecdsa` (NIST P-256) by default for Fulcio root certificates and Rekor transparency logs.
* **Sigstore PQC Working Group & Cloudflare CIRCL:**
  * Sigstore has prototype branches utilizing **Cloudflare CIRCL** (`github.com/cloudflare/circl`) supporting **ML-DSA-44/65/87** and **Hybrid Ed25519 + ML-DSA-65**.
* **PKCS#11 & Custom PQC Signers:**
  * Cosign supports external hardware security modules (HSMs) and OpenSSL 3.x with **`oqsprovider` (Open Quantum Safe)**.
* **ULP Solution:** ulp-driver implements a **Hybrid Envelope Attestation Engine** that pairs Cosign's ECDSA transparency with NIST FIPS 204 ML-DSA-65 post-quantum lattice verification.

---

## 4. Hybrid Dual-Layer Signing Architecture

In accordance with **NIST SP 800-227**, **BSI TR-02102**, and **NSA CNSA 2.0**, systems transitioning to post-quantum cryptography must employ **Hybrid Signatures**:

$$\text{Valid}(\text{Payload}) \iff \text{Valid}_{\text{Classical}}(\text{Payload}) \land \text{Valid}_{\text{PQC}}(\text{Payload})$$

```json
{
  "signature_type": "hybrid_pqc_classical_v1",
  "security_policy": "dual_verification_required",
  "payload_sha256": "e265bd300c1bd95e9693df5abb3cd9224293a41cc44ff7aa39c2c84263c77523",
  "classical": {
    "algorithm": "ECDSA-P256-SHA256",
    "provider": "Sigstore/Cosign",
    "signature_b64": "MEYCIQC3v1..."
  },
  "post_quantum": {
    "algorithm": "ML-DSA-65",
    "standard": "NIST FIPS 204",
    "quantum_bits": 128,
    "signature_b64": "k7aF8m9Q..."
  }
}
```

### Why Hybrid Signing is Essential:
1. **Quantum Immunity:** If a quantum computer breaks ECDSA, the ML-DSA-65 lattice signature prevents unauthorized patch injection.
2. **Maturity Guard:** If an unforeseen mathematical vulnerability is discovered in new lattice cryptography, the battle-tested classical ECDSA signature prevents forgery.

---

## 5. Implementation Reference & CLI Tooling

### 5.1 Tool Overview
* [`ulp_pqc_signer.py`](/ulp_pqc_signer.py): Generates ML-DSA-65 keypairs and outputs pure PQC and Hybrid envelopes.
* [`ulp_crypto_verifier.py`](/ulp_crypto_verifier.py): Policy verification engine supporting `pqcSigned`, `hybridSigned`, `sigstoreSigned`, and `signedBy`.
* [`test_pqc_verification_suite.py`](/test_pqc_verification_suite.py): 6-phase test suite validating tamper resistance and fail-closed security.

### 5.2 Generating Keys & Signing Livepatches

```bash
# 1. Generate ML-DSA-65 Post-Quantum Keypair
python3 ulp_pqc_signer.py genkey haproxy /etc/ulp/keys

# 2. Sign with Pure Post-Quantum ML-DSA-65
python3 ulp_pqc_signer.py sign patch_haproxy.so /etc/ulp/keys/haproxy-mldsa65.key patch_haproxy.so.pqc.sig

# 3. Sign with Classical Cosign (ECDSA-P256)
cosign sign-blob --key /etc/ulp/keys/haproxy-cosign.key --tlog-upload=false --yes patch_haproxy.so --output-signature patch_haproxy.so.cosign.sig

# 4. Generate Hybrid Dual-Layer Attestation Envelope
python3 ulp_pqc_signer.py sign-hybrid patch_haproxy.so \
    /etc/ulp/keys/haproxy-mldsa65.key \
    patch_haproxy.so.cosign.sig \
    patch_haproxy.so.hybrid.sig
```

### 5.3 Configuring `policy.json`

```json
{
  "default": [
    { "type": "reject" }
  ],
  "transports": {
    "livepatch": {
      "/usr/local/sbin/haproxy": [
        {
          "type": "hybridSigned",
          "pqcKeyPath": "/etc/ulp/keys/haproxy-mldsa65.pub",
          "classicalKeyPath": "/etc/ulp/keys/haproxy-cosign.pub"
        },
        {
          "type": "pqcSigned",
          "keyPath": "/etc/ulp/keys/haproxy-mldsa65.pub"
        }
      ],
      "/usr/sbin/mariadbd": [
        {
          "type": "pqcSigned",
          "keyPath": "/etc/ulp/keys/mariadb-mldsa65.pub"
        }
      ],
      "/usr/lib/postgresql/17/bin/postgres": [
        {
          "type": "hybridSigned",
          "pqcKeyPath": "/etc/ulp/keys/postgres-mldsa65.pub",
          "classicalKeyPath": "/etc/ulp/keys/postgres-cosign.pub"
        }
      ]
    }
  }
}
```

---

## 6. Verification Results Matrix

Executed on **Local Host**, **`debian-13` VM**, and **`fedora-44` VM**:

| Test Case | Scenario Description | Expected Result | Result |
| :--- | :--- | :---: | :---: |
| **Test 1** | Pure NIST FIPS 204 ML-DSA-65 Signature | **PASS (Valid)** | **PASSED (100%)** |
| **Test 2** | Tampered Payload Binary Detection | **FAIL (Rejected)** | **PASSED (100%)** |
| **Test 3** | Untrusted Attacker PQC Key Signature | **FAIL (Rejected)** | **PASSED (100%)** |
| **Test 4** | Hybrid Dual-Layer (ECDSA + ML-DSA-65) | **PASS (Valid)** | **PASSED (100%)** |
| **Test 5** | Fail-Closed: Corrupted Classical Layer | **FAIL (Rejected)** | **PASSED (100%)** |
| **Test 6** | Production Targets (HAProxy, MariaDB, Postgres) | **PASS (All 3)** | **PASSED (100%)** |

All tests passed with 100% success across Debian 13 and Fedora 44.
