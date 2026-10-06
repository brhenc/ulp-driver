//! # pgrust Client: Multi-Threaded Concurrency Stress & Verification Tool
//!
//! Spawns multiple worker threads generating concurrent traffic against pgrust_daemon
//! to verify continuous query execution before, during, and after livepatching.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let port: u16 = std::env::var("PGRUST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5433);

    let host = std::env::var("PGRUST_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let target = format!("{}:{}", host, port);

    let num_threads: usize = std::env::var("PGRUST_THREADS")
        .ok()
        .and_then(|t| t.parse().ok())
        .unwrap_or(16);

    let queries_per_thread: usize = std::env::var("PGRUST_QUERIES")
        .ok()
        .and_then(|q| q.parse().ok())
        .unwrap_or(50);

    println!("===============================================================");
    println!("   PGRUST MULTI-THREADED CONCURRENCY VERIFIER                 ");
    println!("===============================================================");
    println!("[+] Target Address      : {}", target);
    println!("[+] Worker Threads      : {}", num_threads);
    println!("[+] Queries Per Worker  : {}", queries_per_thread);
    println!("[+] Total Query Target  : {}", num_threads * queries_per_thread);
    println!("===============================================================");

    let success_count = Arc::new(AtomicU64::new(0));
    let failure_count = Arc::new(AtomicU64::new(0));
    let shadow_active_count = Arc::new(AtomicU64::new(0));
    let livepatched_version_count = Arc::new(AtomicU64::new(0));

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for thread_idx in 0..num_threads {
        let target_clone = target.clone();
        let succ = success_count.clone();
        let fail = failure_count.clone();
        let shadow_act = shadow_active_count.clone();
        let live_ver = livepatched_version_count.clone();

        handles.push(thread::spawn(move || {
            let mut stream = match TcpStream::connect(&target_clone) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[-] Worker {} connect failed: {}", thread_idx, e);
                    fail.fetch_add(queries_per_thread as u64, Ordering::Relaxed);
                    return;
                }
            };

            let mut reader = BufReader::new(stream.try_clone().unwrap());

            for q_idx in 0..queries_per_thread {
                // Alternating between VERSION check and QUERY execution
                if q_idx % 5 == 0 {
                    if stream.write_all(b"VERSION\n").is_err() {
                        fail.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let mut resp = String::new();
                    if reader.read_line(&mut resp).is_ok() && resp.starts_with("OK ") {
                        succ.fetch_add(1, Ordering::Relaxed);
                        if resp.contains("LIVEPATCHED") {
                            live_ver.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    let cmd = format!("QUERY SELECT * FROM users WHERE tenant_id = {}\n", q_idx);
                    if stream.write_all(cmd.as_bytes()).is_err() {
                        fail.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let mut resp = String::new();
                    if reader.read_line(&mut resp).is_ok() && resp.starts_with("OK ") {
                        succ.fetch_add(1, Ordering::Relaxed);
                        if resp.contains("SHADOW_ACTIVE") {
                            shadow_act.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Small realistic think-time between queries
                thread::sleep(Duration::from_micros(500));
            }

            stream.write_all(b"QUIT\n").ok();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start_time.elapsed();
    let total_succ = success_count.load(Ordering::Relaxed);
    let total_fail = failure_count.load(Ordering::Relaxed);
    let total_live = livepatched_version_count.load(Ordering::Relaxed);
    let total_shadow = shadow_active_count.load(Ordering::Relaxed);

    println!("\n===============================================================");
    println!("                 BENCHMARK EXECUTION RESULTS                   ");
    println!("===============================================================");
    println!("  Elapsed Time            : {:.3?}", elapsed);
    println!("  Successful Requests     : {}", total_succ);
    println!("  Failed Requests         : {}", total_fail);
    println!("  Livepatched Versions Seen: {}", total_live);
    println!("  Shadow Variables Active : {}", total_shadow);
    println!("===============================================================");

    if total_fail > 0 {
        eprintln!("[-] FAILED: Detected request failures under concurrency!");
        std::process::exit(1);
    } else {
        println!("[+] SUCCESS: All {} concurrent requests succeeded with 100% reliability!", total_succ);
    }
}
