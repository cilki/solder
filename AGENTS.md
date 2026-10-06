# Solder Project

Solder is a post-link static merger for ELF shared libraries. It extracts
symbols from shared libraries and merges them directly into executables,
eliminating runtime dependencies.

## Build & Test

`shell.nix` pins the toolchain (cargo, rustc, clippy, rustfmt, binutils, gdb),
so prefix these with `nix-shell --run` if you don't already have one.

```bash
cargo test            # the whole suite; every test is in-tree under #[cfg(test)]
cargo clippy --all-targets
cargo build --release
```

## Trying it on the test fixtures

`test/` holds real dynamically linked binaries together with the libraries they
link against, in `test/libs`. Those sonames are not the host's, so `-L
test/libs` is required — without it `solder` cannot resolve the `DT_NEEDED`
entry and exits with an error.

`--dry-run` writes nothing, so it can be pointed straight at a fixture. It is
the quickest way to see what a change did to extraction:

```bash
./target/release/solder test/md5sum -L test/libs --dry-run
```

A real merge rewrites its input in place and keeps no backup, so merge a copy
and leave the committed fixture alone:

```bash
cp test/grep /tmp/grep
./target/release/solder /tmp/grep -L test/libs -m libpcre2-8.so.0
/tmp/grep --version
```

Each fixture has a `<name>.test` beside it (`test/grep.test`,
`test/md5sum.test`, `test/bash.test`) listing the behaviour a merged binary has
to keep. They are plain bash functions named `test*` that invoke the binary by
name, so running them means putting the merged copy on `PATH` first. There is
no runner yet.

## TO-DO

- A runner for the `test/*.test` suites, so merged binaries get checked
  automatically instead of by hand
