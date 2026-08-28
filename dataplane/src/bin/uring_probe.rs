// SPDX-License-Identifier: GPL-3.0-or-later
//
// Measures what the io_uring receive path costs against a plain recvfrom loop,
// on a burst that is ALREADY sitting in the socket queue. The sender is stopped
// before the clock starts, so this prices the receive side rather than how fast
// the other end can push - a distinction that flattered io_uring by 4x when got
// it wrong the first time.

use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use wingsv_dataplane::{RingConfig, UringReceiver};

const BURST: usize = 8_000;
const ROUNDS: usize = 8;
const PAYLOAD: usize = 1400;

fn main() -> io::Result<()> {
    let (plain_time, plain_count) = measure(ROUNDS, drain_recvfrom)?;
    println!(
        "recvfrom, queued burst : {:>7.1} ns/packet  ({} packets)",
        plain_time.as_nanos() as f64 / plain_count as f64,
        plain_count
    );

    let (uring_time, uring_count) = measure(ROUNDS, drain_uring)?;
    println!(
        "io_uring multishot     : {:>7.1} ns/packet  ({} packets)",
        uring_time.as_nanos() as f64 / uring_count as f64,
        uring_count
    );

    let ratio = (plain_time.as_nanos() as f64 / plain_count as f64)
        / (uring_time.as_nanos() as f64 / uring_count as f64);
    println!("io_uring is {ratio:.2}x the speed of recvfrom");
    Ok(())
}

fn measure<F>(rounds: usize, drain: F) -> io::Result<(Duration, usize)>
where
    F: Fn(&UdpSocket, usize) -> io::Result<(Duration, usize)>,
{
    let mut total = Duration::ZERO;
    let mut packets = 0usize;
    for _ in 0..rounds {
        let (receiver, sender) = pair()?;
        let queued = fill(&sender, BURST);
        let (elapsed, got) = drain(&receiver, queued)?;
        total += elapsed;
        packets += got;
    }
    Ok((total, packets))
}

fn pair() -> io::Result<(UdpSocket, UdpSocket)> {
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    set_rcvbuf(receiver.as_raw_fd(), 256 << 20);
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.connect(receiver.local_addr()?)?;
    Ok((receiver, sender))
}

/// Pushes datagrams until the kernel refuses, so the drain has a real queue.
fn fill(sender: &UdpSocket, target: usize) -> usize {
    let payload = vec![0u8; PAYLOAD];
    let mut queued = 0usize;
    for _ in 0..target {
        match sender.send(&payload) {
            Ok(_) => queued += 1,
            Err(_) => break,
        }
    }
    queued
}

fn set_rcvbuf(fd: i32, bytes: i32) {
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &bytes as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

fn drain_recvfrom(receiver: &UdpSocket, queued: usize) -> io::Result<(Duration, usize)> {
    let mut buf = vec![0u8; 2048];
    receiver.set_nonblocking(true)?;
    let start = Instant::now();
    let mut got = 0usize;
    while got < queued {
        match receiver.recv(&mut buf) {
            Ok(_) => got += 1,
            Err(_) => break,
        }
    }
    Ok((start.elapsed(), got))
}

fn drain_uring(receiver: &UdpSocket, queued: usize) -> io::Result<(Duration, usize)> {
    let mut uring = UringReceiver::new(receiver.as_raw_fd(), RingConfig::default())?;
    let mut bytes = 0usize;
    let mut busy = Duration::ZERO;
    let mut got = 0usize;
    while got < queued {
        // Only the drains that actually carried packets are timed. A datagram
        // that finds no free buffer is DROPPED rather than queued, so the run
        // always ends on one drain that waits out the full timeout and returns
        // nothing; counting that would measure the timeout, not the receive path.
        let start = Instant::now();
        let delivered = uring.drain(|packet| bytes += packet.len())?;
        if delivered == 0 {
            break;
        }
        busy += start.elapsed();
        got += delivered;
    }
    std::hint::black_box(bytes);
    Ok((busy, got))
}
