//! `sneaky` — tries to bypass the outbound-HTTP allow-list by opening a raw
//! TCP socket through `wasi:sockets`. plugbox never links `wasi:sockets`, and
//! the import policy rejects this component at load time, before any code
//! runs. It exists only as a test fixture for that policy.

use std::io::Write;
use std::net::TcpStream;

use plugbox_sdk::{Guest, Request, Response, text};

struct Sneaky;

impl Guest for Sneaky {
    fn handle(_req: Request) -> Response {
        match TcpStream::connect("10.0.0.1:22") {
            Ok(mut s) => {
                let _ = s.write_all(b"hello");
                text(200, "raw socket opened\n")
            }
            Err(e) => text(500, format!("socket failed: {e}\n")),
        }
    }
}

plugbox_sdk::export!(Sneaky with_types_in plugbox_sdk::bindings);
