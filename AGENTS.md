# Solder Project

Solder is a post-link static merger for ELF shared libraries. It extracts
symbols from shared libraries and merges them directly into executables,
eliminating runtime dependencies.

## Build & Test

```bash
cargo build --release
./target/release/solder ./binary -m libfoo.so.1 
# Restore original, run solder, test
cp ./grep.bak ./grep && chmod u+w ./grep
./target/release/solder ./grep -m libpcre2-8.so.0 ```
