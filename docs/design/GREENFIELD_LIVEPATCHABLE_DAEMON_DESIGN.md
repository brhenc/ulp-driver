# Architectural Design: Greenfield Rust Daemons for Userspace Livepatching (ULP)

**Subsystem**: Livepatch-Native Application Architecture  
**Target Systems**: Rust High-Performance Proxies (HAProxy replacement), Database Engines, Network Daemons  
**Document**: `docs/design/GREENFIELD_LIVEPATCHABLE_DAEMON_DESIGN.md`  
**Status**: Architectural Specification & Implementation Guidelines  

---

## 1. Executive Summary

Traditional C/Rust daemons are difficult to livepatch because compilers aggressively inline functions, randomize struct layouts (`repr(Rust)`), and interleave critical lock acquisitions across deeply nested call stacks.

When designing a high-performance proxy or database engine in Rust **from scratch**, incorporating a **Livepatch-Native Architecture** simplifies runtime updates, eliminates lock inversions, and enables continuous zero-downtime evolution without process restarts.

---

## 2. The 5 Core Pillars of a Livepatch-Native Daemon

```
                                  LIVEPATCH-NATIVE ARCHITECTURE
      ┌────────────────────────────────────────────────────────────────────────────────────────┐
      │                                                                                        │
      │   1. COMPILER & SYMBOL DISCIPLINE                                                      │
      │      - Strategic #[inline(never)] at stage boundaries                                  │
      │      - Guaranteed 16-byte function alignment (CET endbr64)                             │
      │      - Stable symbol export manifest (build-time symbols.json)                         │
      │                                                                                        │
      │   2. DATA EVOLUTION & TYPE-SAFE EXTENSION SLOTS                                        │
      │      - Built-in Extension Bag (ArcSwap/TypeMap) on core Connection/Stream structs       │
      │      - RAII Drop cleanup guarantees for attached shadow variables                      │
      │                                                                                        │
      │   3. CONCURRENCY & EPOCH-BASED RCU (USERS PACE RCU)                                    │
      │      - Immutable configuration & routing pipelines swapped via ArcSwap                 │
      │      - Zero lock contention across patched boundaries                                  │
      │                                                                                        │
      │   4. EVENT LOOP QUIESCENCE CHECKPOINTS                                                 │
      │      - Event loop yields at known generation barriers (drain without thread freezes)   │
      │                                                                                        │
      │   5. IN-PROCESS INTROSPECTION & CONTROL PROTOCOL                                       │
      │      - UNIX control socket reporting VMA bases, symbol offsets, and active epochs      │
      │                                                                                        │
      └────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Pillar 1: Compiler & Symbol Control

### A. Strategic Function Boundaries
In Rust, the compiler optimizes away function calls via whole-program optimization (WPO) and Link-Time Optimization (LTO). To make a function patchable, enforce:

```rust
// Core pipeline stages must have distinct symbol entry points
#[no_mangle]
#[inline(never)]
pub extern "C" fn process_http_request_headers(
    ctx: &mut StreamContext,
    headers: &mut HeaderMap,
) -> FilterResult {
    // Stage logic
}
```

### B. Function Alignment (16-Byte CET Trampoline Guarantee)
The ULP kernel driver requires 8-byte or 16-byte natural alignment to perform atomic instruction overlays and emit CET/IBT `endbr64` headers.
* Configure in `.cargo/config.toml` or `rustc` flags:
  ```toml
  [target.x86_64-unknown-linux-gnu]
  rustflags = ["-C", "llvm-args=-align-all-functions=4"] # Aligns functions to 16 bytes (2^4)
  ```

### C. Automated Symbol Manifest Generation
Generate a `symbols.json` during the cargo build process that maps internal stage names to ELF symbol offsets, eliminating the need for `nm` scraping at runtime.

---

## 4. Pillar 2: Data Structure Evolution & Extension Slots

### The Struct Expansion Hazard
In Rust, changing `struct StreamSession` layout in a patch corrupts memory across unpatched modules.

### The Solution: Built-In Typed Extension Bags
Include a built-in, out-of-band extension map on all long-lived heap structs:

```rust
use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct StreamSession {
    pub id: u64,
    pub client_addr: std::net::SocketAddr,
    pub created_at_ns: u64,
    
    // Built-in lock-free extension slot for livepatch state
    pub extensions: parking_lot::RwLock<HashMap<u32, Box<dyn Any + Send + Sync>>>,
}

impl StreamSession {
    /// Retrieve or lazily initialize versioned livepatch state
    pub fn get_or_insert_extension<T: Any + Send + Sync + Default>(&self, slot_id: u32) -> &T {
        // Safe access without struct reallocation
    }
}
```

---

## 5. Pillar 3: Epoch-Based RCU for Routing & Filter Pipelines

### The Lock Inversion Trap
Livepatching a function that holds a mutex while calling another function that acquires an altered lock hierarchy causes deadlocks.

### The Livepatch-Native Pattern: Immutable Pipeline Swapping via `ArcSwap`
Treat the proxy pipeline (HTTP parsers, rate limiters, upstream pools) as an immutable tree swapped atomically via RCU:

```rust
use arc_swap::ArcSwap;
use std::sync::Arc;

pub struct ProxyEngine {
    // Hot-swappable filter pipeline
    pub pipeline: ArcSwap<FilterPipeline>,
}

impl ProxyEngine {
    pub fn handle_connection(&self, stream: TcpStream) {
        // Load current epoch pipeline lock-free
        let current_pipeline = self.pipeline.load();
        current_pipeline.execute(stream);
    }

    /// Livepatch or configuration update swaps entire pipeline atomically
    pub fn update_pipeline(&self, new_pipeline: FilterPipeline) {
        self.pipeline.store(Arc::new(new_pipeline));
    }
}
```

---

## 6. Pillar 4: Event-Loop Quiescence Checkpoints

Instead of requiring the kernel driver to freeze threads via `ptrace` or scan thread stack IPs, the event loop provides natural synchronization barriers:

```rust
pub async fn worker_event_loop(worker_id: usize, mut rx: EventReceiver) {
    let mut epoch_tracker = EpochGuard::new(worker_id);
    
    while let Some(event) = rx.recv().await {
        // 1. Enter connection epoch
        epoch_tracker.enter_active();
        
        // 2. Process event
        process_event(event).await;
        
        // 3. Mark quiescent point (Safe point for livepatching)
        epoch_tracker.mark_quiescent();
    }
}
```

---

## 7. Pillar 5: Control Socket & Self-Introspection

A livepatch-native proxy should expose a local UNIX control socket (`/run/haproxy-rs/control.sock`) with introspection commands:
1. `GET /vma-info`: Returns current process base address, heap segments, and mapped `.so` libraries.
2. `GET /epoch-status`: Returns active query counters across worker threads.
3. `POST /quiesce-barrier`: Cooperatively pauses new connections for 500µs to allow instantaneous atomic kernel patching.
4. `GET /version-dag`: Reports currently active livepatch commit history.

---

## 8. Summary: Comparison Matrix

| Architectural Dimension | Traditional C Daemon (e.g. HAProxy C) | Livepatch-Native Rust Daemon |
| :--- | :--- | :--- |
| **Inlining** | Heavy macro and compiler inlining across files | Explicit `#[inline(never)]` stage entrypoints |
| **Function Alignment** | Default compiler alignment (often 1 or 4 bytes) | Strict 16-byte alignment (`-align-all-functions=4`) |
| **Struct Modifications** | Breaking ABI hazard; requires shadow variable hooks | Built-in `ExtensionBag` / `TypeMap` on core structs |
| **Pipeline Updates** | In-place code rewriting of C functions | `ArcSwap` RCU pipeline swapping + code patching |
| **Quiescence** | Relies on kernel thread IP inspection | Cooperative event-loop epoch checkpoints |
| **Introspection** | External `nm` / `/proc/maps` parsing | Dedicated UNIX introspection socket |
