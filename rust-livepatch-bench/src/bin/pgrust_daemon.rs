//! # pgrust Daemon: Multi-Threaded PostgreSQL-Compatible Rust Server
//!
//! Models the concurrent connection engine, state tracking, and query execution
//! of a production Rust database server for userspace livepatching verification.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use ulp_shadow::{ShadowMetrics, UlpShadowExt};

pub static RUNNING: AtomicBool = AtomicBool::new(true);
pub static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(1);
pub static TOTAL_QUERIES_SERVED: AtomicU64 = AtomicU64::new(0);

/// Core Connection Structure representing an active database session.
/// Physical layout is FIXED and immutable at runtime.
#[repr(C)]
pub struct PgConnection {
    pub id: u32,
    pub user_id: u32,
    pub created_at: u64,
}

impl Drop for PgConnection {
    fn drop(&mut self) {
        // Automatic RAII shadow cleanup on drop
        unsafe {
            self.shadow_clear_all();
        }
    }
}

pub struct PgServerState {
    pub connections: RwLock<HashMap<u32, Arc<PgConnection>>>,
}

lazy_static::lazy_static! {
    pub static ref SERVER_STATE: Arc<PgServerState> = Arc::new(PgServerState {
        connections: RwLock::new(HashMap::new()),
    });
}

// ----------------------------------------------------------------------------
// Target Functions for Livepatching
// ----------------------------------------------------------------------------

/// Original version banner function.
/// When livepatched, the driver overwrites this function's prologue with a jump
/// to the replacement function returning the livepatched banner.
#[no_mangle]
#[inline(never)]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn pgrust_get_version() -> &'static str {
    let s = std::hint::black_box("pgrust 17.0.0-vanilla-rust");
    std::hint::black_box(s);
    std::hint::black_box(s);
    std::hint::black_box(s);
    s
}

/// Original query processor.
/// When livepatched, this function is redirected to attach and update
/// dynamic shadow variables on the PgConnection struct.
#[no_mangle]
#[inline(never)]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn pgrust_process_query(_conn: &PgConnection, query: &str) -> u32 {
    TOTAL_QUERIES_SERVED.fetch_add(1, Ordering::Relaxed);
    // Baseline query cost
    let cost = std::hint::black_box(query.len() as u32);
    std::hint::black_box(cost);
    cost
}

// ----------------------------------------------------------------------------
// Connection & Protocol Handler
// ----------------------------------------------------------------------------

fn handle_client(mut stream: TcpStream, conn: Arc<PgConnection>) {
    let reader = BufReader::new(stream.try_clone().expect("Failed to clone socket"));

    for line in reader.lines() {
        if !RUNNING.load(Ordering::Relaxed) {
            break;
        }

        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == "QUIT" || trimmed == "EXIT" {
            break;
        }

        let response = if trimmed == "VERSION" {
            let fn_ptr: extern "C" fn() -> &'static str = std::hint::black_box(pgrust_get_version);
            let ver = fn_ptr();
            format!("OK {}\n", ver)
        } else if trimmed.starts_with("QUERY ") {
            let q = &trimmed[6..];
            let fn_ptr: extern "C" fn(&PgConnection, &str) -> u32 = std::hint::black_box(pgrust_process_query);
            let result_code = fn_ptr(&conn, q);
            
            // Check if shadow metrics have been dynamically attached by a livepatch
            let shadow_info = unsafe {
                if let Some(quota) = conn.shadow_get::<ShadowMetrics>(0x2001) {
                    format!(
                        " [SHADOW_ACTIVE: queries={}, rate_limited={}]",
                        quota.query_counter.load(Ordering::Relaxed),
                        quota.is_rate_limited.load(Ordering::Relaxed)
                    )
                } else {
                    " [SHADOW_INACTIVE]".to_string()
                }
            };

            format!("OK code={}{}\n", result_code, shadow_info)
        } else if trimmed == "STATS" {
            let active_conns = SERVER_STATE.connections.read().len();
            let total_q = TOTAL_QUERIES_SERVED.load(Ordering::Relaxed);
            format!("OK active_connections={} total_queries={}\n", active_conns, total_q)
        } else if trimmed == "PID" {
            format!("OK pid={}\n", std::process::id())
        } else {
            "ERR unknown command\n".to_string()
        };

        if stream.write_all(response.as_bytes()).is_err() {
            break;
        }
    }

    // Unregister connection on disconnect
    SERVER_STATE.connections.write().remove(&conn.id);
}

fn main() {
    let port: u16 = std::env::var("PGRUST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5433);

    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[-] Failed to bind pgrust daemon to {}: {}", bind_addr, e);
            std::process::exit(1);
        }
    };

    println!("===============================================================");
    println!("   PGRUST DAEMON: MULTI-THREADED POSTGRESQL RUST SERVER        ");
    println!("===============================================================");
    println!("[+] Process ID (PID)      : {}", std::process::id());
    println!("[+] Listening Address     : {}", bind_addr);
    println!("[+] Initial Version       : {}", pgrust_get_version());
    println!("[+] Target Function Addrs :");
    println!("    - pgrust_get_version  : 0x{:x}", pgrust_get_version as *const () as usize);
    println!("    - pgrust_process_query: 0x{:x}", pgrust_process_query as *const () as usize);
    println!("===============================================================");

    let mut conn_threads = Vec::new();

    // Set non-blocking listener with small timeout for clean termination
    listener.set_nonblocking(true).ok();

    while RUNNING.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let conn = Arc::new(PgConnection {
                    id,
                    user_id: 1000 + (id % 10),
                    created_at: now,
                });

                SERVER_STATE.connections.write().insert(id, conn.clone());

                let handle = thread::spawn(move || {
                    handle_client(stream, conn);
                });
                conn_threads.push(handle);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("[-] Accept error: {}", e);
                break;
            }
        }
    }

    println!("[*] Shutting down pgrust daemon...");
    for h in conn_threads {
        h.join().ok();
    }
}
