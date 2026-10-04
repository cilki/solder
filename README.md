# solder

> Don't rebuild it, `solder` it!
>
> Actually, you should probably try rebuilding it first, but if that doesn't
> work out, then you can `solder` it.

**solder** is a post-link static merger for ELF executables. It extracts symbols
from shared libraries and fuses them directly into executables, removing runtime
dependencies altogether.

## Partial static linking

The primary use case for `solder` is _partial static linking_.

Depending on what build tool you're using, you can have vastly different
experiences. Sometimes you can simply add `-l:libexample.a` to your `LDFLAGS`
and it works first try. Sometimes it's not that easy. If you find yourself
hacking `configure` scripts or generated Makefiles to accomplish this, consider
just post-processing your binary with `solder` instead.

You don't have to recompile anything. Just give it your executable and the
shared objects you want statically linked. Just note the following libraries are
excluded because static linking them can cause unpleasant problems (even when
you properly static link them at build time).

- ld-linux
- ld-musl
- linux-vdso
- linux-gate
- libc
- libm
- librt
- libpthread
- libdl
- libresolv
- libnss\_
- libgcc_s

Only symbols that are actually used will be merged into the final executable.
For example, `md5sum` is only about 56K, but it dynamically links
`libcrypto.so.3` which is 6.5M.

### Nixpkgs

For binaries built from [nixpkgs](https://github.com/NixOS/nixpkgs), you can
make them fully portable to other systems by first `solder`-ing in the
libraries, then `patchelf`-ing the library path back to normal. I've used this
to take advantage of the vast quantity of software available in nixpkgs on
embedded systems where I can't install `nix`, etc.

## Usage

```sh
# Merge all possible libraries into the executable (in-place)
solder ./myapp

# Merge only specific libraries
solder ./myapp -m libfoo.so.1 -m libbar.so.2

# Add additional library search paths
solder ./myapp -L /opt/mylibs -L ./libs

# Preview what would happen without writing output
solder ./myapp --dry-run
```

## How It Works

- Parses the executable's dynamic section to identify imported symbols
- Resolves which shared libraries provide those symbols (using regular library
  search paths)
- Extracts the minimal set of code/data needed
  - Uses symbolic execution to identify jump tables in .rodata
- Applies relocations and creates trampolines for any remaining external calls
- Appends new `PT_LOAD` segments containing the merged code: read-execute for
  the code and trampolines, read-write for the data and the slots the dynamic
  loader fills in, read-only for the rebuilt symbol and relocation tables
- Patches GOT entries to point directly to the merged symbols
- Removes the merged libraries from `DT_NEEDED`

## Limitations

- x86_64 only
- We can't merge `dlopen` libraries
