Real dynamically linked ELF binaries to `solder`, and in `libs/` the shared
libraries they were linked against. Those sonames are not expected to be
installed on the host, so `-L test/libs` is required for `solder` to resolve
them:

```sh
./target/release/solder test/md5sum -L test/libs --dry-run
```

Beside each binary, `<name>.test` lists the behaviour a merged copy has to
keep, as bash functions named `test*` that invoke the binary by name. A merge
rewrites its input in place and keeps no backup, so merge a copy of a fixture
rather than the committed one.

