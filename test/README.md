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


`aarch64/` holds `libpages.so.1`, a small aarch64 library the extractor's
aarch64 tests read, and the `libpages.c` it was built from with GCC 15 on an
aarch64 host:

```sh
cc -O2 -fPIC -fno-section-anchors -shared -Wl,-soname,libpages.so.1 \
   -o libpages.so.1 libpages.c
```
