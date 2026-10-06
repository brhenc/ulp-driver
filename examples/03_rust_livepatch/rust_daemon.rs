/*
 * ulp-driver: ULP Example 3 - Rust Target Daemon
 *
 * Demonstrates livepatching a compiled Rust service with ABI safety,
 * symbol resolution, and 16-byte absolute trampolines.
 */

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

const SOCKET_PATH: &str = "/tmp/ulp_example_rust.sock";

/*
 * TARGET FUNCTION: rust_get_rate_limit
 *
 * Requirements for Rust livepatchable functions:
 * 1. #[no_mangle]: Prevents compiler name mangling for clean symbol discovery.
 * 2. #[inline(never)]: Guarantees the function exists as an independent call target.
 * 3. pub extern "C": Enforces standard C calling convention (System V AMD64 ABI).
 */
#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_get_rate_limit() -> u32 {
    100
}

fn handle_client(mut stream: UnixStream) {
    // Calling through std::hint::black_box prevents intra-crate constant folding
    let get_limit: extern "C" fn() -> u32 = std::hint::black_box(rust_get_rate_limit);
    let limit = get_limit();

    let resp = if limit == 100 {
        format!("STATUS: v1.0.0-rust [UNPATCHED] | rate_limit={} req/s | engine=standard\n", limit)
    } else {
        format!("STATUS: v1.0.1-rust [LIVEPATCHED] | rate_limit={} req/s | engine=hotpatched_accel\n", limit)
    };
    let _ = stream.write_all(resp.as_bytes());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--query" {
        let mut stream = UnixStream::connect(SOCKET_PATH).expect("Failed to connect to daemon socket");
        let mut buf = String::new();
        stream.read_to_string(&mut buf).expect("Failed to read response");
        print!("{}", buf);
        return;
    }

    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH).expect("Failed to bind socket");
    println!("[rust_daemon] PID {} listening on {}", std::process::id(), SOCKET_PATH);
    println!("[rust_daemon] rust_get_rate_limit symbol: {:p}", rust_get_rate_limit as *const ());

    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_client(s),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("[rust_daemon] accept error: {:?}", e);
                break;
            }
        }
    }

    let _ = std::fs::remove_file(SOCKET_PATH);
}
