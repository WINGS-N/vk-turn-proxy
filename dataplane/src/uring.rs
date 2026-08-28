// SPDX-License-Identifier: GPL-3.0-or-later

//! io_uring receive path for a UDP socket.
//!
//! Two things make this cheaper than a read per datagram:
//!
//! - a registered buffer ring, so the kernel takes a buffer itself when a
//!   datagram lands instead of the caller supplying one per call, and
//! - multishot receive, where one submitted operation keeps completing for every
//!   datagram that arrives rather than being resubmitted each time.
//!
//! The cost of that is a buffer ring that can run dry: a datagram arriving with
//! no free buffer is dropped by the kernel, not queued. Recycling therefore has
//! to keep up, which is why buffers are returned as soon as a batch is processed.

use io_uring::{cqueue, opcode, types, IoUring};
use std::io;
use std::os::fd::RawFd;
use std::time::Duration;

/// How the ring is sized. Defaults suit one relay flow; a busier socket wants
/// more buffers, since every datagram in flight holds one.
#[derive(Clone, Copy, Debug)]
pub struct RingConfig {
    pub entries: u32,
    pub buffers: u16,
    pub buffer_len: usize,
    pub wait_timeout: Duration,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            entries: 512,
            buffers: 512,
            // Enough for the tunnel MTU plus TURN and WRAP framing without the
            // kernel having to truncate.
            buffer_len: 2048,
            wait_timeout: Duration::from_millis(50),
        }
    }
}

/// Drains a UDP socket with io_uring. Does not own the descriptor: the caller
/// keeps it open for as long as the receiver is used.
pub struct UringReceiver {
    ring: IoUring,
    buffers: BufferRing,
    fd: RawFd,
    config: RingConfig,
    armed: bool,
}

impl UringReceiver {
    pub fn new(fd: RawFd, config: RingConfig) -> io::Result<Self> {
        let ring = IoUring::builder()
            .setup_cqsize(config.entries * 4)
            // One thread submits and one thread reaps, which lets the kernel skip
            // the locking it would otherwise need, and completions are gathered
            // rather than delivered by interrupt.
            .setup_single_issuer()
            .setup_coop_taskrun()
            .build(config.entries)?;
        let buffers = BufferRing::new(&ring, config.buffers, config.buffer_len)?;
        Ok(Self {
            ring,
            buffers,
            fd,
            config,
            armed: false,
        })
    }

    /// Waits for datagrams and hands each one to `on_packet`. Returns how many
    /// were delivered, which is zero when the socket stayed quiet for the
    /// configured timeout.
    pub fn drain<F>(&mut self, mut on_packet: F) -> io::Result<usize>
    where
        F: FnMut(&[u8]),
    {
        if !self.armed {
            self.arm()?;
        }
        let timespec = types::Timespec::new()
            .sec(self.config.wait_timeout.as_secs())
            .nsec(self.config.wait_timeout.subsec_nanos());
        let args = types::SubmitArgs::new().timespec(&timespec);
        match self.ring.submitter().submit_with_args(1, &args) {
            Ok(_) => {}
            // The wait deadline expiring is how a quiet socket reports itself.
            Err(ref err) if err.raw_os_error() == Some(libc::ETIME) => {}
            Err(err) => return Err(err),
        }

        let mut delivered = 0usize;
        let mut recycled = false;
        let mut rearm = false;
        for cqe in self.ring.completion() {
            let result = cqe.result();
            if result <= 0 {
                // A terminated multishot, including the ring running dry, has to
                // be resubmitted before anything else will be received.
                rearm = true;
                continue;
            }
            if let Some(index) = cqueue::buffer_select(cqe.flags()) {
                on_packet(self.buffers.payload(index, result as usize));
                self.buffers.release(index);
                recycled = true;
            }
            delivered += 1;
            if !cqueue::more(cqe.flags()) {
                rearm = true;
            }
        }
        // Publishing the ring tail once per batch, not per datagram: it is a word
        // the kernel also reads, and writing it per packet is pure overhead.
        if recycled {
            self.buffers.publish();
        }
        if rearm {
            self.armed = false;
        }
        Ok(delivered)
    }

    fn arm(&mut self) -> io::Result<()> {
        let entry = opcode::RecvMulti::new(types::Fd(self.fd), self.buffers.group())
            .build()
            .user_data(RECV_USER_DATA);
        // Safety: the entry borrows nothing; the buffer ring it names outlives it.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| io::Error::other("io_uring submission queue is full"))?;
        }
        self.armed = true;
        Ok(())
    }
}

const RECV_USER_DATA: u64 = 1;

/// A registered ring of receive buffers. The kernel picks one per datagram and
/// reports which it used, so nothing is handed over on the submission side.
struct BufferRing {
    entries: *mut types::BufRingEntry,
    storage: Vec<u8>,
    count: u16,
    mask: u16,
    tail: u16,
    buffer_len: usize,
    map_len: usize,
    group: u16,
}

impl BufferRing {
    fn new(ring: &IoUring, count: u16, buffer_len: usize) -> io::Result<Self> {
        if !count.is_power_of_two() {
            return Err(io::Error::other("buffer count must be a power of two"));
        }
        let map_len = count as usize * std::mem::size_of::<types::BufRingEntry>();
        // The ring is shared with the kernel, so it needs its own mapping rather
        // than living inside a Vec the allocator may move.
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if memory == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let entries = memory.cast::<types::BufRingEntry>();
        let group = 0;
        unsafe {
            ring.submitter()
                .register_buf_ring_with_flags(entries as u64, count, group, 0)?;
        }
        let mut this = Self {
            entries,
            storage: vec![0u8; count as usize * buffer_len],
            count,
            mask: count - 1,
            tail: 0,
            buffer_len,
            map_len,
            group,
        };
        for index in 0..this.count {
            this.release(index);
        }
        this.publish();
        Ok(this)
    }

    fn group(&self) -> u16 {
        self.group
    }

    fn payload(&self, index: u16, len: usize) -> &[u8] {
        let start = index as usize * self.buffer_len;
        let end = start + len.min(self.buffer_len);
        &self.storage[start..end]
    }

    /// Hands a buffer back to the kernel. Not visible until `publish`.
    fn release(&mut self, index: u16) {
        let slot_index = (self.tail & self.mask) as usize;
        let address = self.storage.as_ptr() as u64 + (index as usize * self.buffer_len) as u64;
        unsafe {
            let slot = self.entries.add(slot_index);
            (*slot).set_addr(address);
            (*slot).set_len(self.buffer_len as u32);
            (*slot).set_bid(index);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    fn publish(&mut self) {
        unsafe {
            let tail = types::BufRingEntry::tail(self.entries).cast_mut();
            std::ptr::write_volatile(tail, self.tail);
        }
    }
}

impl Drop for BufferRing {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.entries.cast(), self.map_len);
        }
    }
}
