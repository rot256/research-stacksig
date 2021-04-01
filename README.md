# StackSig; Ring Signatures from Stacking

Benchmark of applying the [Stacking Sigma compiler](https://eprint.iacr.org/2021/422) to Schnorr (over Ristretto25519): in order to obtain efficient [ring signatures](https://en.wikipedia.org/wiki/Ring_signature) from discrete log and random oracles.
The resuling ring signature / 1-of-many proof has a size `64 + 64 * log(n)` bytes e.g. `64 + 64 * log(2^10) = 704 B` for a ring with 1024 signers.

# Running the benchmarks

To reproduce the benchmarks, run:

```
RUSTFLAGS="-C target-cpu=native" cargo bench
```

# Warning

This code is not suitable for production use.

# LICENSE

This code is released under GPLv3. 