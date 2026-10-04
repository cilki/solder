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
- libc.so
- libm.so
- librt.so
- libpthread
- libdl.so
- libresolv
- libnss\_
- libgcc_s.so

Those are matched as prefixes of the `DT_NEEDED` soname, so the `libc.so` entry
excludes `libc.so.6` but leaves something like `libcrypto.so.3` mergeable.

Only symbols that are actually used will be merged into the final executable.
For example, `md5sum` is only about 56K, but it dynamically links
`libcrypto.so.3` which is 6.5M.

### Inherited dependencies

Merging a library moves its code into the executable but not its own
dependencies. `libcrypto.so.3` resolves `ZSTD_compress` through its
`DT_NEEDED` on `libzstd.so.1`, so once libcrypto is gone from the executable's
`DT_NEEDED` nothing in the link chain provides that symbol — and the merged
binary would not start at all.

So a dependency of a merged library is added to the executable's own
`DT_NEEDED` when all of the following hold:

- the executable does not already link it,
- it is not itself being merged away, and
- it exports at least one symbol the extracted code refers to.

A dependency nothing in the extracted code calls stays dropped. One that
`solder` cannot find on disk is inherited without that last check, since
guessing it away risks an executable that will not load; you'll get a warning
saying so. `--dry-run` lists whatever gets inherited, so you can see up front
which dependencies survive the merge.

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

# A prefix of the soname works too, if you'd rather not spell out the version
solder ./myapp -m libfoo

# Add additional library search paths
solder ./myapp -L /opt/mylibs -L ./libs

# Preview what would happen without writing output
solder ./myapp --dry-run

# Report what solder is doing (only warnings and errors are printed by default)
RUST_LOG=info solder ./myapp
```

A `-m` entry that matches no `DT_NEEDED` soname, or that matches only
never-mergeable ones, is an error rather than a silent no-op — quietly merging
a subset of what you asked for is almost never what you wanted.

The executable is rewritten in place and no backup is kept, so hold on to a
copy of anything you can't rebuild.

### Library resolution

Each `DT_NEEDED` soname is looked up in the first of these that contains it:

1. `DT_RPATH` of the executable
2. `$SYSROOT/lib`, if `SYSROOT` is set in the environment
3. `-L` directories, in the order given
4. `LD_LIBRARY_PATH`
5. `DT_RUNPATH` of the executable
6. `/etc/ld.so.cache`
7. `/lib64`, `/usr/lib64`, `/lib`, `/usr/lib`, `/lib/x86_64-linux-gnu`,
   `/usr/lib/x86_64-linux-gnu`

That is the dynamic linker's own order with `$SYSROOT/lib` and `-L` spliced in
after `DT_RPATH`. Note that `-L` therefore does *not* override an executable
that was linked with an `RPATH`.

## How It Works

- Parses the executable's dynamic section to identify imported symbols
- Resolves which shared libraries provide those symbols (see
  [Library resolution](#library-resolution))
- Extracts the minimal set of code/data needed
  - Uses symbolic execution to identify jump tables in .rodata
- Applies relocations and creates trampolines for any remaining external calls
- Appends new `PT_LOAD` segments containing the merged code: read-execute for
  the code and trampolines, read-write for the data and the slots the dynamic
  loader fills in, read-only for the rebuilt symbol and relocation tables
- Patches GOT entries to point directly to the merged symbols
- Removes the merged libraries from `DT_NEEDED`, and moves onto the executable
  any `DT_NEEDED` of theirs that still provides a symbol the extracted code
  calls (see [Inherited dependencies](#inherited-dependencies))

## Limitations

- x86_64 only
- We can't merge `dlopen` libraries
- Extracted code may not contain relocations that need the library's own GOT
  (`R_X86_64_GOTPCREL` and friends); `solder` refuses the merge rather than
  producing a broken binary
- A copy-relocated data symbol (`R_X86_64_COPY`) coming from a library we're
  removing has to be zero-initialized, since its initial value currently can't
  be carried over
