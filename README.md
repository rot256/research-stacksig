# StackSig; Ring Signatures from Stacking

Benchmark of applying the [Stacking Sigma compiler](https://eprint.iacr.org/2021/422) to Schnorr (over Ristretto25519): in order to obtain efficient [ring signatures](https://en.wikipedia.org/wiki/Ring_signature) from discrete log and random oracles.
The resulting ring signature / 1-of-many proof has a size `64 + 64 * log(n)` bytes e.g. `64 + 64 * log(2^10) = 704 B` for a ring with 1024 signers.

# Benchmarks

```
test bench_sig2    ... bench:   4,020,133 ns/iter (+/- 675,344)
test bench_sig4    ... bench:   8,102,077 ns/iter (+/- 893,862)
test bench_sig8    ... bench:  12,375,899 ns/iter (+/- 1,304,431)
test bench_sig16   ... bench:  17,691,196 ns/iter (+/- 1,885,039)
test bench_sig32   ... bench:  24,365,603 ns/iter (+/- 1,967,199)
test bench_sig64   ... bench:  33,854,217 ns/iter (+/- 2,376,623)
test bench_sig128  ... bench:  49,570,680 ns/iter (+/- 1,887,752)
test bench_sig256  ... bench:  76,397,846 ns/iter (+/- 2,289,558)
test bench_sig512  ... bench: 126,863,799 ns/iter (+/- 2,758,139)
test bench_sig1024 ... bench: 224,208,287 ns/iter (+/- 3,148,849)
test bench_sig2048 ... bench: 413,886,499 ns/iter (+/- 2,861,665)
test bench_sig4096 ... bench: 812,572,834 ns/iter (+/- 2,724,649)
```

On a single core of AMD EPYC 7601 (32-Core Processor).

```
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 23
model		: 1
stepping	: 2
microcode	: 0x1000065
cpu MHz		: 2199.984
cache size	: 512 KB
physical id	: 0
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush 
          mmx fxsr sse sse2 syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm rep_good nopl 
          cpuid extd_apicid tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 
          x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor 
          lahf_lm cmp_legacy cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw 
          perfctr_core ssbd ibpb vmmcall fsgsbase tsc_adjust bmi1 avx2 smep bmi2 rdseed 
          adx smap clflushopt sha_ni xsaveopt xsavec xgetbv1 virt_ssbd arat arch_capabilities
bugs		: fxsave_leak sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 4399.96
TLB size	: 1024 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 40 bits physical, 48 bits virtual
power management:
```

# Running the benchmarks

To reproduce the benchmarks:

1. Get the latest nightly Rust from [Rustup](https://rustup.rs/).
2. Run `RUSTFLAGS="-C target-cpu=native" cargo bench`

# Warning

This code is not suitable for production use.

# LICENSE

This code is released under GPLv3.

