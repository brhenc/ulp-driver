# ulp-driver: Continuous In-Flight Binary Livepatching via Git-Like DAG & Delta Object Architecture

**Subsystem**: Userspace Livepatching (ULP) Versioning & Continuous Evolution Engine  
**Project**: ulp-driver (Evolution of ulp-driver)  
**Target Environment**: Linux 6.x / 7.x (x86_64), Rust Database Engines (`pgrust`), C/C++ Daemons  
**Document**: `docs/design/CONTINUOUS_LIVEPATCHING_GIT_ARCHITECTURE.md`  
**Reference**: Pro Git (Chapter 10: Git Internals)  

---

## 1. Executive Vision: Continuous In-Flight Livepatching

In standard continuous deployment (CD) pipelines, shipping a new version ($V_{k+1}$) of a software daemon requires:
1. Building a whole new binary artifact.
2. Stopping the active process ($V_k$).
3. Restarting the process on $V_{k+1}$.

For high-performance database engines (such as `pgrust`, PostgreSQL, MariaDB) and stateful networking daemons, restarts cause severe disruption:
* In-flight transactions are aborted or rolled back.
* Established TCP client connections and sessions are severed.
* Memory caches (buffer pools, query execution plans, metadata catalogs) are lost, causing "cold-cache" latency spikes.

**ulp-driver** introduces **Continuous In-Flight Binary Evolution**:
Instead of redeploying binaries, the running daemon process is continuously evolved through a sequence of versioned, atomic binary livepatches:

$$V_0 \xrightarrow{\Delta_{0 \to 1}} V_1 \xrightarrow{\Delta_{1 \to 2}} V_2 \xrightarrow{\Delta_{2 \to 3}} V_3 \dots$$

Operators can navigate the version history of a running process—applying incremental updates, branching hotfixes, and rolling back to earlier generations—using an object model and workflow modeled directly after **Git internals**.

```
                   [ LIVE PROCESS VERSION DAG (PID 14209) ]

      (Commit C0) ───► (Commit C1) ───► (Commit C2) ───► (Commit C3: HEAD)
     [Base Binary]     [Auth Fix]       [Query Accel]   [Dynamic Pooling]
           │                                 ▲
           │                                 │
           └─────────► (Commit C1.1) ────────┘
                      [Emergency Hotfix]
```

---

## 2. Mapping Git Internals to Binary Livepatching

Git's core architecture (Pro Git Chapter 10) is a content-addressable key-value object store combined with a directed acyclic graph (DAG) of commit objects. We map these concepts directly to in-memory binary livepatching:

```
┌─────────────────┬──────────────────────────────────┬────────────────────────────────────────────────────────┐
│ Git Concept     │ Git Implementation               │ ulp-driver ULP Implementation                      │
├─────────────────┼──────────────────────────────────┼────────────────────────────────────────────────────────┤
│ **Blob**        │ Uncompressed file byte content   │ **Code & Relocation Chunk**: Function machine code     │
│                 │ (`git hash-object`)              │ bytes, CET trampolines, DWARF symbols, type metadata.  │
├─────────────────┼──────────────────────────────────┼────────────────────────────────────────────────────────┤
│ **Tree**        │ Directory hierarchy mapping      │ **Process Memory Layout**: Map of symbol names and     │
│                 │ filenames -> Blob SHA-1          │ virtual addresses -> Function Patch Blobs.             │
├─────────────────┼──────────────────────────────────┼────────────────────────────────────────────────────────┤
│ **Commit**      │ Snapshot metadata: tree, parent, │ **Livepatch Generation Snapshot**: Tree ref, parent    │
│                 │ author, commit message, GPG sig  │ livepatch commit(s), target binary hash, state schema. │
├─────────────────┼──────────────────────────────────┼────────────────────────────────────────────────────────┤
│ **Tag**         │ Named reference with signature   │ **Cryptographic Release**: Cosign/GPG signed release   │
│                 │ pointing to a specific commit    │ pinned to verified production milestone.               │
├─────────────────┼──────────────────────────────────┼────────────────────────────────────────────────────────┤
│ **Ref / HEAD**  │ Pointer to current commit        │ **Active PID State Pointer**: Points to the currently  │
│                 │ (`refs/heads/main`)              │ active livepatch generation for a given process PID.   │
├─────────────────┼──────────────────────────────────┼────────────────────────────────────────────────────────┤
│ **Packfile**    │ Pack of objects compressed with  │ **Livepatch Bundle**: Self-contained ELF payload       │
│                 │ byte-level delta compression     │ containing only binary deltas against previous state.  │
└─────────────────┴──────────────────────────────────┴────────────────────────────────────────────────────────┘
```

---

## 3. Data Structures & Object Modeling

### 3.1 The Livepatch Object Store

All livepatch artifacts are stored in a content-addressed directory structure (`/var/lib/ulp/objects/` or in-kernel table):

```
.ulp/
├── HEAD                        # Points to active ref (e.g. ref: refs/heads/production)
├── refs/
│   ├── heads/
│   │   └── production          # Contains 32-byte SHA-256 commit hash
│   └── tags/
│       └── v1.2.0-hotpatch
└── objects/
    ├── 4a/
    │   └── f819...             # Blob: Compiled function replacement (ELF section)
    ├── 8e/
    │   └── 310a...             # Tree: Virtual address translation table
    └── c2/
        └── d74b...             # Commit: Version metadata, parent hash, migration hooks
```

### 3.2 Commit Object Schema (`struct ulp_commit`)

```c
struct ulp_commit {
    __u8  commit_id[32];        /* SHA-256 content hash of this commit descriptor */
    __u8  parent_id[32];        /* SHA-256 of previous generation (0 for initial base) */
    __u8  tree_id[32];          /* Root Tree object hash defining memory layout */
    __u64 timestamp_ns;         /* Wall clock timestamp of creation */
    __u32 schema_version;       /* State/Shadow variable schema generation */
    char  author[64];           /* Author identity */
    char  message[256];         /* Commit changelog message */
    __u32 num_relocations;      /* Number of symbols modified */
    __u8  signature[64];        /* Ed25519 / ECDSA-P256 cryptographic signature */
};
```

### 3.3 Tree Object Schema (`struct ulp_tree_entry`)

A tree object represents a complete catalog of function replacements active in a given version:

```c
struct ulp_tree_entry {
    char  symbol_name[64];      /* Target function name (e.g., pgrust_process_query) */
    __u64 target_vaddr;         /* Base binary target virtual address */
    __u64 patch_vaddr;          /* Current replacement function virtual address */
    __u8  blob_id[32];          /* SHA-256 of function binary payload */
    __u32 func_len;             /* Instruction length of target */
    __u32 tramp_type;           /* 0 = REL5 (5-byte), 1 = ABS16 (16-byte CET) */
};
```

---

## 4. Binary Diffing & Delta Trampoline Chaining

When moving between versions ($V_k \to V_{k+1}$), ulp-driver avoids rebuilding and re-injecting unchanged code:

### 4.1 Incremental Function Diffs
1. **ELF Disassembly Diffing**: Compares function machine code between $V_k$ and $V_{k+1}$. Unchanged functions remain bound to their existing memory allocations.
2. **Minimal Relocation Deltas**: Only functions whose AST or compiled instructions changed receive new allocations in the target process.

### 4.2 Trampoline Update Strategies

```
 Strategy A: Direct Retargeting (Atomic Overwrite)
 ──────────────────────────────────────────────────
   [ Target Function @ 0x401500 ]
         │
         ├── Before: 16-byte JMP ──► [ Patch V1 @ 0x7f1000 ]
         │
         └── After:  16-byte JMP ──► [ Patch V2 @ 0x7f2000 ]  (Atomic 8-byte word swap)

 Strategy B: Delta Trampoline Chaining
 ──────────────────────────────────────────────────
   [ Target Function @ 0x401500 ] ──► [ Patch V1 @ 0x7f1000 ] ──► [ Patch V2 @ 0x7f2000 ]
```

* **Direct Retargeting**: The kernel driver overwrites the 64-bit destination address in the original CET trampoline. This provides $O(1)$ call performance identical to the unpatched binary.
* **Preservation Rollback Journal**: The driver maintains reverse deltas ($\Delta_{k \to k-1}$), enabling single-instruction rollback to any prior commit in the DAG without process restart.

---

## 5. State & Data Structure Evolution: The Shadow Variable Engine

Livepatching logic is straightforward; livepatching **data structures** is where memory corruption and ABA bugs typically occur.

### 5.1 The Struct Expansion Problem
In database systems like `pgrust`, `struct PgConnection` is allocated on the heap across hundreds of active client sessions. If $V_2$ adds a new field (`rate_limit_quota: u32`), expanding the struct dynamically in memory is impossible because existing compiled code expects fields at fixed offsets.

### 5.2 Versioned Shadow Variables

ulp-driver uses **Versioned Out-of-Band Shadow Tables**:

```
                         [ IN-FLIGHT HEAP OBJECT ]
                           ┌──────────────────┐
                           │   PgConnection   │ (Addr: 0x7fff0010)
                           │   - id: 42       │
                           │   - user_id: 100 │
                           └────────┬─────────┘
                                    │
               ┌────────────────────┴────────────────────┐
               ▼ (Key: 0x7fff0010, Tag: 0x2001)          ▼ (Key: 0x7fff0010, Tag: 0x2002)
   ┌───────────────────────┐                 ┌───────────────────────┐
   │ Shadow State V1       │                 │ Shadow State V2       │
   │ (Commit C1 Schema)    │                 │ (Commit C2 Schema)    │
   │ - queries_served: 15  │                 │ - rate_limit_max: 500 │
   │ - is_authenticated: 1 │                 │ - token_bucket: 480   │
   └───────────────────────┘                 └───────────────────────┘
```

### 5.3 Lazy vs Eager Migration
* **Lazy Schema Upgrade**: When an existing connection calls a $V_2$ function, the function calls `ulp_shadow_get(conn, SCHEMA_V2)`. If `None`, it initializes default state from $V_1$ metadata on first touch.
* **Rust RAII Destruction Guarantees**: Bound directly to the Rust `Drop` trait:
  ```rust
  impl Drop for PgConnection {
      fn drop(&mut self) {
          unsafe {
              // Unlinks all versioned shadow allocations atomically on object drop
              self.shadow_clear_all();
          }
      }
  }
  ```

---

## 6. Concurrency, Lock Safety & Quiescence Barriers

In an active database daemon executing hundreds of queries concurrently across multiple threads, hotpatching must satisfy three strict safety invariants:

### Invariant 1: Stack Quiescence (No In-Flight Thread Interception)
* The kernel driver scans the instruction pointers (`task_pt_regs(t)->ip`) of **all threads** in the target thread group.
* If any thread is currently executing within the `[target_vaddr, target_vaddr + func_len]` range, the patch operation returns `-EAGAIN` and defers execution to a safe quiescent window.

### Invariant 2: Lock & Futex Safety
* Before replacing a function that acquires or releases a lock (e.g. `parking_lot::RwLock`, database buffer manager latch, or `pthread_mutex_t`), the driver inspects the futex word.
* If the futex is currently held (`val != 0`), patching is deferred until the critical section completes.

### Invariant 3: Epoch-Based Transaction Boundaries (Userspace RCU)
For database transaction isolation:
1. Active transactions in flight complete under Epoch $E_k$ using $V_k$ logic.
2. New incoming transactions enter under Epoch $E_{k+1}$ using $V_{k+1}$ logic.
3. When Epoch $E_k$'s active transaction counter drops to zero, the driver marks $V_k$'s temporary migration state as safely reclaimable.

---

## 7. Reference Target: `pgrust` Evolution Pipeline

To validate ulp-driver under real-world conditions, we use `pgrust`—a high-performance, multi-threaded Rust database server.

### Roadmap of Continuous Evolutionary Livepatches

| Generation | Commit | Evolutionary Feature Added to Active Running Daemon | Verification Metric |
| :---: | :--- | :--- | :--- |
| **$V_0$** | `C0` (Base) | Baseline PostgreSQL-compatible query parser & executor. | Baseline benchmark (15k QPS). |
| **$V_1$** | `C1` | **CVE Security Patch**: Fixes query parser buffer bounds and adds audit log. | Zero dropped connections; audit log active. |
| **$V_2$** | `C2` | **Shadow Variable Schema Evolution**: Adds per-connection rate-limiting & telemetry state. | Rate limiter active; shadow memory verified leak-free. |
| **$V_3$** | `C3` | **Engine Acceleration**: Vectorized JSON query processor hotpatched into active executor. | Query latency reduced 40%; cache retained. |
| **$V_{\text{rollback}}$** | `C1` | **Atomic Rollback**: Operator issues `git-ulp revert HEAD~2` to restore $V_1$ state. | System reverts to $V_1$ behavior instantly with 0 downtime. |

---

## 8. Summary of Next Implementation Steps

1. **Implement Git-Like Livepatch Manifest & DAG Engine (`ulp_git.rs` / `ulp_dag.c`)**:
   - Content-addressable blob hashing (SHA-256).
   - Commit DAG traversal (parent/child commit graph).
2. **Implement Binary Delta Generator**:
   - Compares two shared library iterations and produces a minimal changeset `.ulp-delta`.
3. **Build Epoch Quiescence Barrier in `pgrust`**:
   - Transaction boundary hooks allowing safe generation transitions.
4. **End-to-End Multi-Version Stress Suite**:
   - Continuous livepatching of `pgrust` over thousands of queries while applying $V_0 \to V_1 \to V_2 \to V_3 \to V_1$.
