// SPDX-License-Identifier: GPL-3.0-or-later
//
// Packet data plane for the vk-turn-proxy relay.
//
// The Go relay reads and writes one datagram per syscall through the runtime's
// poller. That is fine until the syscall itself is what costs, at which point the
// only way further is to stop making one per packet. This crate exists to own
// that path: it takes a socket and drives it with io_uring, so a burst is drained
// with one wait instead of one call per datagram.
//
// It is built as a staticlib and linked into the Go binary, so the relay stays a
// single executable with no IPC and no second process to supervise. Rust owns the
// loop and the socket once it is handed over; the boundary is crossed to start
// and stop it, never per packet.

pub mod uring;

pub use uring::{RingConfig, UringReceiver};
