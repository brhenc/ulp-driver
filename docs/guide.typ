#set page(
  paper: "a4",
  margin: (top: 2.2cm, bottom: 2.2cm, left: 2.2cm, right: 2.2cm),
  header: context {
    if here().page() > 1 [
      #grid(
        columns: (1fr, 1fr),
        align(left)[#text(size: 8.5pt, fill: rgb("#555555"), font: "Liberation Sans")[ulp-driver: Userspace Livepatching Guide]],
        align(right)[#text(size: 8.5pt, fill: rgb("#555555"), font: "Liberation Sans")[Demystifying the "Voodoo"]]
      )
      #line(length: 100%, stroke: 0.4pt + rgb("#cccccc"))
    ]
  },
  footer: context {
    if here().page() > 1 [
      #line(length: 100%, stroke: 0.4pt + rgb("#cccccc"))
      #grid(
        columns: (1fr, 1fr),
        align(left)[#text(size: 8.5pt, fill: rgb("#777777"), font: "Liberation Sans")[Confidential & Engineering Reference]],
        align(right)[#text(size: 8.5pt, fill: rgb("#777777"), font: "Liberation Sans")[Page #here().page()]]
      )
    ]
  }
)

#set text(font: "Liberation Sans", size: 10pt, fill: rgb("#222222"))
#set par(justify: true, leading: 0.65em)
#set heading(numbering: "1.1")

#show heading: it => {
  set text(font: "Liberation Sans", fill: rgb("#1a2a3a"), weight: "bold")
  if it.level == 1 {
    block(above: 1.8em, below: 1.0em)[
      #text(size: 16pt)[#it.body]
      #v(0.2em)
      #line(length: 100%, stroke: 1.5pt + rgb("#1e3d59"))
    ]
  } else if it.level == 2 {
    block(above: 1.4em, below: 0.8em)[
      #text(size: 13pt)[#it.body]
    ]
  } else {
    block(above: 1.1em, below: 0.6em)[
      #text(size: 11pt, fill: rgb("#2b4a6f"))[#it.body]
    ]
  }
}

#show raw: it => {
  if it.block {
    block(
      fill: rgb("#f5f7fa"),
      inset: 8pt,
      radius: 4pt,
      stroke: 0.5pt + rgb("#d1d5db"),
      width: 100%,
      text(font: "Liberation Mono", size: 8.5pt)[#it]
    )
  } else {
    box(
      fill: rgb("#eaeff5"),
      inset: (x: 3pt, y: 1.5pt),
      radius: 2pt,
      text(font: "Liberation Mono", size: 8.8pt)[#it]
    )
  }
}

#let callout(title: "Note", body, color: rgb("#1e3d59"), bg: rgb("#f0f4f8")) = {
  block(
    fill: bg,
    stroke: (left: 3pt + color),
    inset: (left: 10pt, right: 10pt, top: 8pt, bottom: 8pt),
    radius: (right: 4pt),
    width: 100%,
    [
      #text(weight: "bold", fill: color, size: 9.5pt)[#title]
      #v(0.3em)
      #text(size: 9pt)[#body]
    ]
  )
}

// -------------------------------------------------------------
// Title Page / Header Block
// -------------------------------------------------------------

#align(center)[
  #v(0.5cm)
  #text(size: 22pt, weight: "bold", fill: rgb("#1e3d59"))[Demystifying Userspace Livepatching]
  #v(0.5em)
  #text(size: 12pt, style: "italic", fill: rgb("#445566"))[An Engineer's Guide to ulp-driver]
  #v(0.3em)
  #text(size: 10.5pt, fill: rgb("#667788"))[From Virtual Memory & x86_64 Machine Code to Kernel Invariants, Plan 9 VFS, and Cryptographic Provenance]
  #v(0.8em)
  #line(length: 60%, stroke: 1pt + rgb("#1e3d59"))
  #v(0.6em)
  #grid(
    columns: (1fr, 1fr),
    align(left)[#text(size: 9.5pt)[*Author:* Google DeepMind Advanced Agentic Coding\ *Architecture:* Linux 6.x/7.x x86_64]],
    align(right)[#text(size: 9.5pt)[*Target Daemons:* HAProxy, MariaDB, Postgres\ *Document Version:* 3.1 (Post-Hardening)]]
  )
  #v(0.6cm)
]

#callout(title: "Audience & Prerequisites", color: rgb("#2b6cb0"), bg: rgb("#ebf4ff"))[
  This guide assumes *basic competence in the C programming language* (pointers, structs, functions, loops, memory addresses), but assumes *zero prior experience with binary exploitation, kernel driver internals, or machine code manipulation*. If hotpatching running memory feels like "black magic" or "voodoo," this guide exists to show you exactly how the CPU, virtual memory, and kernel cooperate to make it ordinary, deterministic systems engineering.
]

#pagebreak()

#v(1em)
#text(size: 18pt, weight: "bold", fill: rgb("#1e3d59"))[Table of Contents]
#v(0.5em)
#line(length: 100%, stroke: 1.5pt + rgb("#1e3d59"))
#v(1em)

#outline(title: none, indent: 1.5em, depth: 2)

#pagebreak()

= The Illusion of "Voodoo"

When you write a C program, you write structured, human-readable text:

```c
int calculate_bill(int hours, int rate) {
    if (hours < 0) return 0;
    return hours * rate;
}
```

You compile it with `gcc`, run it, and when you want to change it, you edit the C file, recompile, stop the program, and start the new executable.

*Userspace Livepatching (ULP)* changes this rule:
1. The program is already running in production (e.g., HAProxy handling 50,000 active TCP connections, or MariaDB with a 64 GB buffer pool).
2. You cannot restart the process.
3. You cannot disconnect the clients.
4. Yet, you want `calculate_bill()` to immediately execute different logic across all CPU cores.

To a C programmer, this feels like impossible magic. How can you change a function while a CPU is in the middle of executing it? How can you bypass operating system protections that prevent modifying running code? How does the modified program survive reboots and worker reloads?

The answer begins by shedding the high-level illusion of C and understanding what a running program *actually* is inside computer hardware.

= How a C Program Actually Lives in Memory

== The CPU Does Not Know About C
The CPU hardware (an Intel or AMD x86_64 processor) has no concept of C, variables, types, or functions. The CPU only knows three things:
1. *Registers*: Tiny, blazingly fast in-chip storage slots (`%rax`, `%rbx`, `%rsp`, `%rip`, etc.).
2. *The Instruction Pointer (`%rip`)*: A 64-bit register holding the memory address of the *very next machine instruction* to execute.
3. *The Fetch-Decode-Execute Loop*: The CPU reads bytes from the address pointed to by `%rip`, decodes what instruction those bytes represent, executes it, advances `%rip`, and repeats billions of times per second.

```
       +-------------------------------------------------------------+
       |                     CPU Core Execution Loop                 |
       |                                                             |
       |     +--------+        +-----------------+        +--------+ |
       |     |  %rip  | -----> |  Memory Address | -----> | Opcode | |
       |     +--------+        +-----------------+        +--------+ |
       |         ^                                            |      |
       |         |                                            v      |
       |    Advance / Jump <----------------------------- Execute    |
       +-------------------------------------------------------------+
```

== The Virtual Memory Address Space
When the Linux kernel launches your program (`execve`), it creates an isolated *Virtual Address Space* for that process. This address space is divided into memory regions called *Virtual Memory Areas (VMAs)*, which you can see in real time by reading `/proc/<PID>/maps`:

```text
555555554000-555555558000 r-xp 00000000 ... /usr/local/sbin/haproxy  (.text / Code)
555555558000-555555559000 r--p 00004000 ... /usr/local/sbin/haproxy  (.rodata)
555555559000-55555555a000 rw-p 00005000 ... /usr/local/sbin/haproxy  (.data / Globals)
7ffff7dc0000-7ffff7fe0000 r-xp 00000000 ... /usr/lib/libc.so.6       (Shared Libraries)
7ffffffde000-7ffffffff000 rw-p 00000000 ... [stack]                  (Call Stack)
```

Notice the permissions column (`r-xp`, `rw-p`):
- *`r` (Read)*: The CPU can read data from this page.
- *`w` (Write)*: The CPU can write data to this page.
- *`x` (Execute)*: The CPU's `%rip` is allowed to jump here and run instructions.

== The W^X (Write XOR Execute) Security Boundary
Modern operating systems enforce *W^X*: a page of memory may be _writable_ (like the heap and stack), or it may be _executable_ (like program code), but *never both at the same time*.

If your C program tries to modify its own code:
```c
void *func_ptr = (void *)calculate_bill;
*(char *)func_ptr = 0x90; // Attempt to overwrite first byte with NOP
```
The CPU's Memory Management Unit (MMU) catches this, detects that the VMA has permissions `r-xp` (no `w`), and fires a hardware page fault exception. The Linux kernel translates this into a `SIGSEGV` signal, and your program instantly crashes: *Segmentation Fault*.

_Livepatching exists entirely to safely, atomically, and legitimately navigate this boundary._

= The Core Livepatching Trick: The Trampoline

== You Never Rewrite the Function
When engineers first hear of livepatching, they often imagine replacing all 500 lines of an old function with 500 lines of new code. *This is not how livepatching works.*

Instead, livepatching uses a *Trampoline*:
1. You compile your new, fixed function and place it somewhere else in memory.
2. You take the *very first instruction* of the original, broken function.
3. You overwrite just the first few bytes with an unconditional jump instruction (`jmp`) pointing directly to your new function.

```
  CALLER PROCESS                            ORIGINAL FUNCTION
+----------------+                       +-----------------------+
| ...            |                       | [ PROLOGUE ]          |
| call 0x401000  | --------------------> | 0x401000: jmp 0x7FFF..| ----+
| ...            |                       | 0x401010: push %rbp   |     |
+----------------+                       | ...                   |     |
                                         +-----------------------+     |
                                                                       |
                                            NEW PATCH FUNCTION         |
                                         +-----------------------+     |
                                         | 0x7FFF...             |<----+
                                         | endbr64               |
                                         | [ NEW BUGFIX LOGIC ]  |
                                         | ret                   |
                                         +-----------------------+
```

When any thread in the application calls `calculate_bill()`, the CPU lands on the first byte, immediately executes your `jmp`, and lands in your new bugfix code. The old broken code behind the jump is simply never executed.

== The Anatomy of an x86_64 Trampoline
There are two primary ways to encode a jump instruction on 64-bit x86 architecture.

=== 1. The 5-Byte Relative Jump (`0xE9 rel32`)
The 5-byte relative jump is the most compact jump possible:
- Byte 0: `0xE9` (Opcode for `JMP rel32`)
- Bytes 1–4: A 32-bit signed integer representing the offset from the *end of the jump instruction* to the *target address*.

```text
Relative Offset = Target_Address - (Source_Address + 5)
```

- *Advantage:* Fits in very short functions (only 5 bytes long).
- *Disadvantage:* A 32-bit signed offset can only reach addresses within plus or minus 2 gigabytes (0x7FFFFFFF bytes). If the patch library is loaded further away in 64-bit virtual memory, a 5-byte jump cannot reach it.

=== 2. The 16-Byte Absolute Trampoline (CET & 64-Bit Safe)
When the destination is anywhere in the 64-bit address space, or when modern security features like *Intel CET (Control-flow Enforcement Technology)* are active, we use a 16-byte absolute trampoline:

```nasm
f3 0f 1e fa                   ; endbr64 (CET Indirect Branch Landing Pad)
48 b8 34 12 fc f7 ff 7f 00 00 ; movabs $0x7ffff7fc1234, %rax (Patch Address)
ff e0                         ; jmp *%rax (Indirect Jump to new function)
90                            ; nop padding to 16 bytes
```

*Why `endbr64` matters:* Modern Linux kernels and glibc enable Intel IBT (Indirect Branch Tracking). If a CPU jumps indirectly to an address that does not begin with the 4-byte `endbr64` signature (`f3 0f 1e fa`), the hardware fires a `#CP` (Control Protection) fault and terminates the process. ulp-driver strictly inserts `endbr64` at the head of every absolute trampoline.

= How the Kernel Writes to Read-Only Code

If userspace cannot write to `r-xp` code pages, how does our kernel driver do it?

The kernel operates in *Ring 0 (Supervisor Mode)*. While the MMU still blocks writes to read-only virtual addresses, the kernel has direct control over the page tables and physical RAM frames.

In `ulp-driver/ulp_driver.c`, we use `access_process_vm()` and `get_user_pages_remote()`:
1. The driver takes the target PID and virtual address.
2. It asks the Linux MM subsystem to find the underlying *physical page frame* in RAM backing that virtual address.
3. The kernel maps that physical page into the *kernel's own virtual memory* using `kmap_local_page()` with read-write permissions.
4. The kernel writes the trampoline bytes directly into the physical memory frame.
5. The kernel unmaps the page and executes a translation lookaside buffer (TLB) flush.

The target process's VMA permissions never change; to userspace, the page remains strictly `r-xp`. But the physical memory underneath has been surgically altered.

= The Multi-Core Hazard: Concurrency & Torn Writes

This is where standard hacking tutorials fail and enterprise systems crash. 

== The Disaster of the "Torn Write"
Imagine HAProxy is running on a 64-core server.
- *Core 0* is executing `get_check_status_info()`.
- *Core 1* is our kernel driver overwriting the first 16 bytes with a jump.

What happens if Core 0 fetches instructions from memory *at the exact same nanosecond* that Core 1 has written the first 8 bytes, but *before* Core 1 has written the remaining 8 bytes?

Core 0 reads half of the old instruction and half of the new instruction. This is called a *Torn Instruction Read*. The CPU tries to decode meaningless garbage bytes, cannot recognize the opcode, and instantly crashes the entire server daemon with `SIGILL` (Illegal Instruction).

== Solution 1: Natural 8-Byte Atomic Overlays
On x86_64, the CPU hardware guarantees that any 8-byte write (`uint64_t`) that is *8-byte aligned* (its address is a multiple of 8) is performed *atomically* in a single clock cycle. It is impossible for another CPU core to observe a half-written 8-byte word.

ulp-driver enforces strict 8-byte alignment verification in `ulp_driver.c`:
```c
if (target_vaddr & 0x7) {
    pr_err("[ulp_driver] Target address 0x%llx is not 8-byte aligned! Rejecting torn-write hazard.\n", target_vaddr);
    return -EINVAL;
}
```

== Solution 2: SMP Cache Pipeline Serialization
Even if memory is written atomically, modern CPUs have separate Level 1 *Instruction Caches (I-Cache)* and *Data Caches (D-Cache)*. Core 1 modified the D-Cache, but Core 0 might still have the old bytes cached in its I-Cache or instruction prefetch queue!

To solve this, ulp-driver issues an Inter-Processor Interrupt (IPI) to force every CPU core to flush its instruction prefetch queue:
```c
on_each_cpu(smp_mb_ipi, NULL, 1);
```
Every CPU core stops what it is doing, executes a serializing barrier (`cpuid`), invalidates its pipeline, and re-fetches the newly patched bytes.

== Solution 3: Thread Quiescence Verification
Before overwriting memory, what if a thread in HAProxy is currently paused (e.g. preempted by the scheduler) *right on byte 4 of the 16 bytes we are about to overwrite*? When that thread wakes up, it will resume execution in the middle of our jump instruction!

In `ulp_driver.c`, `ulp_verify_thread_quiescence()` iterates over every thread in the target process (`/proc/$PID/task/*`):
```c
for_each_thread(task, t) {
    struct pt_regs *regs = task_pt_regs(t);
    if (regs->ip >= target_vaddr && regs->ip < target_vaddr + tramp_len) {
        return -EBUSY; // Thread is inside the danger zone! Retry later.
    }
}
```
If any thread is executing inside the prologue window, the driver refuses to patch and returns `-EBUSY`, protecting the application from desynchronization.

= Surviving Reboots and Worker Reloads: The Kprobe Engine

A common limitation of userspace livepatching is that it only affects the memory of currently running processes. If an administrator runs `systemctl reload haproxy`, the old master forks a new worker and terminates the old one. If you only patched the old worker, the new worker starts completely unpatched!

ulp-driver solves this permanently by living inside the kernel.

```
       USERSPACE EXECUTION                    KERNEL KPROBE HOOKS
    +-----------------------+              +-----------------------+
    | systemctl reload      |              |                       |
    | haproxy               |              |                       |
    +-----------+-----------+              |                       |
                |                          |                       |
                | fork()                   | kprobe:wake_up_new_task
                +------------------------> | Lockless RCU copy of  |
                |                          | active patch registry |
                | execve()                 |                       |
                | (loads new binary)       | kprobe:arch_setup_add |
                +------------------------> | task_work_add(TWA)    |
                |                          +-----------+-----------+
                |                                      |
                | <------------------------------------+
                | (Pokes trampoline in process context
                |  BEFORE main() executes first opcode!)
                v
    +-----------------------+
    | New Process Starts    |
    | (Already Livepatched!)|
    +-----------------------+
```

== Why Early-Boot Livepatching Used to Deadlock
During our early development, we noticed that if the kernel driver tried to patch a process directly inside the `arch_setup_additional_pages` kprobe, the system deadlocked during early boot when `systemd` was spawning hundreds of processes concurrently.

*Why?* The `arch_setup_additional_pages` kprobe runs deep inside `load_elf_binary()` while holding the target process's `mmap_lock` (a memory management read-write semaphore). If the driver tried to call memory allocation or page lookup functions that also required locks, it caused an *AB-BA lock inversion deadlock*.

== The Solution: `task_work_add(..., TWA_RESUME)`
In modern Linux, the kernel provides `task_work_add()`. Instead of modifying memory immediately inside the kprobe, the driver schedules a tiny callback:
```c
task_work_add(current, &ework->work, TWA_RESUME);
```
The kprobe returns immediately in less than 50 nanoseconds with zero lock contention. 

Then, right before the new process returns to userspace for the very first time—after all kernel ELF loading locks have been released, but before the CPU executes the first userspace instruction of `main()`—the kernel runs our `ulp_exec_task_work_fn` in clean, sleepable, preemptible process context. 

The binary wakes up in userspace *already livepatched*.

= The Plan 9 VFS File Interface & Fail-Closed Arming Gate

== The "Rootkit Dilemma"
A userspace livepatching driver has the ability to write executable machine code into arbitrary processes. In the security world, this is identical to what advanced malware or rootkits attempt to do:
- If a web server running as user `www-data` is compromised, can the attacker use the livepatching driver to inject shellcode into `sshd` or `systemd`?
- If an attacker gains root, can they leave a persistent backdoor that covertly hooks authentication functions across reboots?

To solve this, ulp-driver implements the *Plan 9 "Everything is a File" architecture* and a *Fail-Closed Security State Machine*.

== Standard File Semantics on `/dev/ulp`
Instead of using complex `ioctl()` calls (which upstream Linux maintainers discourage due to ABI brittleness and compat padding bugs), `/dev/ulp` behaves like a standard Plan 9 device file:

#table(
  columns: (1fr, 3fr),
  fill: (x, y) => if y == 0 { rgb("#1e3d59") } else if calc.even(y) { rgb("#f8fafc") } else { none },
  stroke: 0.5pt + rgb("#d1d5db"),
  [#text(weight: "bold", fill: white)[File Operation]], [#text(weight: "bold", fill: white)[Role in ulp-driver]],
  [`open("/dev/ulp")`], [Enforces Mode `0600` (`root:root` with `CAP_SYS_ADMIN`). Allocates a session context.],
  [`read(fd, buf, ...)`], [Streams real-time binary `struct ulp_event` telemetry records from the in-kernel `kfifo`.],
  [`poll()` / `epoll`], [Wakes up instantly when kernel events occur (`POLLIN`) or buffer overflow occurs (`POLLERR`).],
  [`write(fd, buf, ...)`], [Ingests version-tolerant commands via `copy_struct_from_user()` (`struct ulp_cmd_v1`).],
  [`close(fd)`], [Destroys the session. If the session was armed, immediately locks the driver.]
)

== The Fail-Closed State Machine
The driver operates under two distinct states:

```
           +-------------------------------------------------------+
           |                ULP_STATE_LOCKED (0)                   |
           |             [Default Production State]                |
           |  - Manual patch pokes REJECTED with -EPERM            |
           |  - New rule additions REJECTED with -EPERM            |
           |  - Existing registered rules ACTIVE on execve/fork    |
           +-------------------------------------------------------+
                       |                               ^
        Explicit ARM   |                               |  Session Closes OR
        by Root Admin  |                               |  Hardware TTL Expires
        (ULP_CMD_ARM)  v                               |  (ULP_CMD_DISARM)
           +-------------------------------------------------------+
           |                 ULP_STATE_ARMED (1)                   |
           |             [Maintenance Window Mode]                 |
           |  - Session bound to active file descriptor            |
           |  - Mandatory hardware TTL countdown timer (max 300s)  |
           |  - Random 32-bit Arming Nonce validates all writes    |
           |  - Livepatch memory injection ALLOWED                 |
           +-------------------------------------------------------+
```

*The Anti-Persistence Invariant:* An administrator cannot accidentally leave the driver unlocked. Even if the maintenance process is killed with `SIGKILL`, the kernel's `timer_list` countdown fires, bumps the nonce, and snaps the driver back into `LOCKED` mode.

= Cryptographic Provenance: CRI-O Style Multi-Provider Signing

To guarantee that only verified, legitimate patches can ever be applied, ulp-driver uses a cryptographic policy engine inspired by container runtimes (*CRI-O* and *Sigstore*).

== The Policy File (`/etc/ulp/policy.json`)
The policy engine enforces *deny-by-default*:
```json
{
  "default": [{ "type": "reject" }],
  "transports": {
    "livepatch": {
      "/usr/local/sbin/haproxy": [
        { "type": "sigstoreSigned", "keyPath": "/etc/ulp/keys/haproxy-cosign.pub" }
      ],
      "/usr/sbin/mariadbd": [
        { "type": "signedBy", "keyType": "GPGKeys", "keyPath": "/etc/ulp/keys/mariadb-team.gpg" }
      ]
    }
  }
}
```

== Dual Cryptographic Providers
ulp-driver natively verifies two independent cryptographic standards:
1. *Sigstore / Cosign (ECDSA-P256)*: Modern cloud-native blob signing. Verifies public key signatures without requiring an external certificate transparency log in offline/air-gapped environments (`--insecure-ignore-tlog=true`).
2. *GPG (OpenPGP RSA-3072)*: Traditional enterprise detached signatures (`.sig`). Verifies against isolated, dedicated keyrings.

If a single byte of a patch payload is altered, or if a patch is signed by an unauthorized key, `tools/ulp_crypto_verifier.py` rejects it with an audit alert *before the kernel is ever commanded to arm*.

= Practical Walkthrough: Patching a Real Function

Let's walk through an actual end-to-end example: livepatching a health check function in HAProxy without dropping active connections.

== Step 1: Identify the Target Symbol
Inspect the running HAProxy binary on disk using `nm` or `objdump`:
```bash
$ nm -B /usr/local/sbin/haproxy | grep get_check_status_info
000000000024f010 T get_check_status_info
```
The target function offset is `0x24f010`.

== Step 2: Write the Replacement C Code
Write a C file containing the replacement logic:
```c
// patch_haproxy.c
int get_check_status_info(void *check) {
    // Custom fix: return healthy status code 0
    return 0;
}
```

== Step 3: Compile Position-Independent Object Code
Compile the patch into a shared library using PIC flags:
```bash
gcc -O2 -fPIC -shared -fno-stack-protector -o patch_haproxy.so patch_haproxy.c
```

== Step 4: Sign the Payload with Cosign
Sign the `.so` using the authorized private key:
```bash
cosign sign-blob --key /etc/ulp/keys/haproxy-cosign.key \
    --tlog-upload=false --output-signature patch_haproxy.so.cosign.sig patch_haproxy.so
```

== Step 5: Apply via `ulp-tui` or Scriptable VFS Write
Launch `sudo ulp-tui`:
1. Use `Up`/`Down` arrows to highlight `HAProxy`.
2. Press `A` to open a 30-second maintenance arming window.
3. Press `P`. The TUI automatically invokes `tools/ulp_crypto_verifier.py`, verifies the Cosign signature against `/etc/ulp/policy.json`, formats `struct ulp_cmd_v1`, writes it to `/dev/ulp`, and disarms the driver.
4. HAProxy's health check is immediately updated across all running worker threads. Zero connections are dropped.

= Summary Glossary & Key Formulas

#table(
  columns: (1fr, 2.5fr),
  fill: (x, y) => if y == 0 { rgb("#1e3d59") } else if calc.even(y) { rgb("#f8fafc") } else { none },
  stroke: 0.5pt + rgb("#d1d5db"),
  [#text(weight: "bold", fill: white)[Term / Concept]], [#text(weight: "bold", fill: white)[Technical Definition]],
  [*Trampoline*], [A small machine code sequence (jump) placed at the beginning of an original function to redirect execution to replacement code.],
  [*CET / IBT*], [Intel Control-flow Enforcement Technology / Indirect Branch Tracking. Requires indirect jumps to land on an `endbr64` instruction (`f3 0f 1e fa`).],
  [*Relative Jump (`0xE9`)*], [5-byte jump with a 32-bit signed offset: Offset = Target - (Source + 5). Range: +/- 2 GB.],
  [*Absolute Jump*], [16-byte jump loading a full 64-bit address into `%rax` and jumping (`jmp *%rax`). Range: entire 64-bit address space.],
  [*W^X Protection*], [Hardware memory policy enforcing that memory is either Writable or Executable, never both.],
  [*Torn Write*], [A concurrency hazard where one CPU core reads memory while another core is halfway through writing it, causing an illegal instruction crash.],
  [*Thread Quiescence*], [The condition where no thread in the process is currently executing inside the memory bytes about to be modified.],
  [*`task_work_add`*], [Linux kernel mechanism to defer work to sleepable process context right before returning to userspace, preventing early-boot deadlocks.],
  [*Plan 9 VFS*], [An interface design where hardware and kernel subsystems are exposed as standard files supporting `read()`, `write()`, and `poll()`.],
  [*Fail-Closed*], [A security architecture where the default state denies all dangerous operations (`ULP_STATE_LOCKED`), requiring explicit timed arming.]
)

#v(2em)
#align(center)[
  #text(size: 9pt, style: "italic", fill: rgb("#777777"))[
    ulp-driver — Enterprise Userspace Livepatching Architecture Guide\
    End of Guide
  ]
]
