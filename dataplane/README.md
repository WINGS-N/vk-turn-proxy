# wingsv-dataplane

Rust packet data plane for the relay, built as a `staticlib` so it links into the
Go binary and the relay stays one executable with no IPC.

Nothing links it yet. It exists because the question "would io_uring make the
relay faster" deserved a measurement rather than an opinion, and the measurement
is `uring-probe`:

```
cargo run --release --bin uring-probe
```

It fills a UDP socket's queue, stops the sender, then drains the burst twice -
once with `recvfrom`, once with io_uring multishot over a registered buffer ring -
and prints ns per datagram. Timing only covers drains that carried packets: a
datagram arriving with no free buffer is dropped by the kernel rather than
queued, so a run always ends on one drain that waits out the timeout and returns
nothing, and counting that measures the timeout instead of the receive path.

Measured on a Ryzen 5 3550H, 1400-byte datagrams, against the Go relay's own
`BenchmarkDrainQueuedBurst` on the same methodology:

| receive path            | ns/datagram |
| ----------------------- | ----------- |
| Go `conn.Read`          | 1141        |
| Rust `recvfrom`         | 913         |
| Rust io_uring multishot | 845         |

io_uring buys about 8% over a plain read, and leaving the Go runtime buys about
25%. Both are small next to what the data path actually spends elsewhere, so this
is not, on its own, a reason to move the relay to Rust.

## Licence

GPL-3.0-or-later, same as the rest of the repository. Written from the kernel
io_uring documentation and the `io-uring` crate API. No code is taken from
csqtt or any other PolyForm-Noncommercial source - that licence is incompatible
with this repository's GPL.
