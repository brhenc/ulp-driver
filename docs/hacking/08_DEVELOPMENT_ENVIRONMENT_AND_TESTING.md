# Development Environment, VM Infrastructure & Test Automation

**Module:** Developer Operations & Testing Guide  
**Test VM:** Debian 13 (Trixie) x86_64 (`192.168.122.171`)  
**Path:** `docs/hacking/08_DEVELOPMENT_ENVIRONMENT_AND_TESTING.md`  

---

## 1. Test Environment Setup & Virtualization

### 1.1 Debian 13 Test VM Access
The test infrastructure runs a dedicated Debian 13 libvirt guest (`debian-13`):
* **Guest IP**: `192.168.122.171`
* **SSH Access**: `ssh root@192.168.122.171`
* **Pre-Installed Daemons**:
  * MariaDB 11.8.6 Enterprise Daemon (`/usr/sbin/mariadbd`, Port 3306)
  * PostgreSQL 17 (`/usr/lib/postgresql/17/bin/postgres`, Port 5432)
  * HAProxy 3.0 (`/usr/local/sbin/haproxy`, Port 8080)
  * pgrust (Rust 1.85 PostgreSQL wire daemon)
  * server_go (Golang high-concurrency microservice)

### 1.2 Managing the VM via `virsh`
```bash
# Check VM status
virsh -c qemu:///system list --all

# Start test guest if stopped
virsh -c qemu:///system start debian-13
```

---

## 2. Building & Loading the ULP Kernel Module

```bash
cd /root/ulp-driver/ulp-driver

# Clean and compile kernel module & CLI tools
make clean && make

# Reload driver into kernel
rmmod ulp_driver 2>/dev/null || true
insmod ulp_driver.ko

# Install user-space utilities
cp ulp_ctl /usr/local/bin/ulp_ctl
cp ulp_inject /usr/local/bin/ulp_inject
chmod 755 /usr/local/bin/ulp_ctl /usr/local/bin/ulp_inject
```

---

## 3. Automated Test Suites & Regression Verification

### 3.1 Multi-Daemon Continuous Evolution Suite
Runs the 5-stage continuous multi-version livepatching lifecycle across `pgrust`, `mariadbd`, `postgres`, and `haproxy`:
```bash
python3 /root/ulp-driver/test_multi_version_continuous_suite.py
```

### 3.2 MariaDB Socket Backlog & maxconn Expansion Benchmark
Validates zero-downtime socket backlog expansion (`ss -tlpn` `Send-Q` $80 \to 300$) and `max_connections` expansion ($151 \to 50,000$):
```bash
python3 /root/ulp-driver/mariadb-livepatch-bench/test_socket_backlog_live_expansion.py
```

### 3.3 Golang Multi-Version Continuous Suite
Validates continuous livepatching on Go daemons under sustained concurrent HTTP traffic:
```bash
python3 /root/ulp-driver/go-livepatch-bench/test_go_continuous_livepatch.py
```

### 3.4 Cross-Architecture 6-ISA Emulation Suite
Validates instruction encoding and livepatching across `x86_64`, `aarch64`, `riscv64`, `s390x`, `ppc64le`, and `loongarch64`:
```bash
python3 cross-arch-bench/run_cross_arch_emulation_suite.py
```

### 3.5 TUI Dashboard Backend Validation
Validates Plan 9 VFS communication, target scanning, arming/disarming, and generation switching:
```bash
python3 /root/ulp-driver/test_ulp_tui_backend.py
```

---

## 4. How to Write a New Livepatch for Any Target Daemon

To create a new livepatch for a new daemon or function:

1. **Step 1: Write the Patch Module (C / Rust / Assembly)**:
   ```c
   // patch_custom.c
   #define _GNU_SOURCE
   #include <stdint.h>

   uint64_t livepatch_my_target_function(void *arg) {
       // New logic / bugfix
       return 42;
   }
   ```
2. **Step 2: Compile to Shared Object**:
   ```bash
   gcc -shared -fPIC -O2 -o patch_custom.so patch_custom.c
   ```
3. **Step 3: Resolve Function Memory Addresses**:
   ```bash
   # Target function address in running process
   TARGET_VADDR=$(python3 -c "import subprocess; ...")
   
   # Injected patch address after ulp_inject
   ulp_inject <target_pid> /path/to/patch_custom.so
   ```
4. **Step 4: Arm Driver & Apply Livepatch**:
   ```bash
   ulp_ctl arm 60
   ulp_ctl apply <target_pid> "my_patch" "my_target_function" 0x<target_vaddr> 0x<patch_vaddr> 16
   ```
5. **Step 5: Verify & Revert**:
   ```bash
   ulp_ctl list
   ulp_ctl revert <target_pid> 0x<target_vaddr>
   ```
