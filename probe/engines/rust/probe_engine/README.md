# probe-engine (Rust)

The primary network-scan engine — fast async port/service scanning (tokio + rusqlite
+ reqwest + clap). `probe/scanner/engines/network/__init__.py` invokes the compiled
binary via subprocess and falls back to a Go scanner (`scanner.go`, built on demand
if `go` is on PATH), then a pure-Python scanner (`native.py`), when this binary isn't
present or can't run on the current host/architecture — so `dread scan` still works
on a machine where this crate hasn't been built. Prefer Rust; the fallbacks exist for
portability, not because Rust is optional to maintain.

## Build
```bash
cargo build --release
```

Binary lands at `target/release/probe-engine`.
