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
excludes `libc.so.6` but leaves something like `libcrypto.so.3` mergeable. A
dependency recorded as a path rather than a soname is matched on its last
component, so spelling glibc `/usr/lib64/libc.so.6` does not get it past the
list.

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

### Constructors and destructors

A library initializes itself from its `DT_INIT_ARRAY` and tears itself down from
its `DT_FINI_ARRAY`, and the loader runs neither once the library is gone from
`DT_NEEDED`. So the merge carries those entries over, in the dependency order of
the libraries they came from, so a library that sets up state another one needs
still goes first:

- Constructors are appended to the executable's `DT_PREINIT_ARRAY`, behind
  whatever it already had there, rather than to its `DT_INIT_ARRAY`. Either
  array would run them ahead of the executable's own constructors, which is the
  order the loader used, but only the preinit phase runs before `_dl_fini` is
  registered with `__cxa_atexit`. That is what keeps `__cxa_atexit`-registered
  C++ static destructors in the exit order they had while the library was
  dynamic, since where they land in the exit-handler LIFO depends on which phase
  registered them.
- Destructors go in front of the executable's own in a rebuilt `DT_FINI_ARRAY`.
  The loader walks that array backwards, so the executable still tears itself
  down first, then each merged library, dependents before dependencies — the
  same order as before the merge.

Only the libraries that actually leave `DT_NEEDED` are treated this way. One the
extraction reached into without removing — nothing imported a symbol from it
directly, so its soname stays — keeps running its own constructors, and copying
them here as well would run them twice.

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

The executable is replaced in place and no backup is kept, so hold on to a copy
of anything you can't rebuild. The replacement itself is atomic — the merged
output is written beside the executable and renamed over it — so a merge that
fails for any reason, `solder`'s own errors included, leaves the input exactly
as it was. Two consequences worth knowing about:

- A copy of the executable that is already running is unaffected, since the
  rename gives the path a new file rather than rewriting the one that process is
  executing from.
- A hard-linked executable is only merged under the name you passed. The other
  names keep pointing at the original file.

### Library resolution

Each `DT_NEEDED` soname is looked up in the first of these that contains it:

1. `DT_RPATH` of the executable, unless it also has a `DT_RUNPATH`
2. `$SYSROOT/lib`, if `SYSROOT` is set in the environment
3. `-L` directories, in the order given
4. `LD_LIBRARY_PATH`
5. `DT_RUNPATH` of the executable
6. `/etc/ld.so.cache`
7. `/lib64`, `/usr/lib64`, `/lib`, `/usr/lib`, `/lib/x86_64-linux-gnu`,
   `/usr/lib/x86_64-linux-gnu`

That is the dynamic linker's own order with `$SYSROOT/lib` and `-L` spliced in
after `DT_RPATH`. Note that `-L` therefore does *not* override an executable
that was linked with an `RPATH`. As with the loader, a `DT_RUNPATH` supersedes
the `DT_RPATH` of the same object entirely rather than being searched after it.

`DT_RPATH` and `DT_RUNPATH` entries go through the same dynamic string token
substitution the loader applies, so an executable that ships its libraries
beside itself (`-Wl,-rpath,'$ORIGIN/libs'`) resolves them from there:

- `$ORIGIN` / `${ORIGIN}` — the directory holding the executable, symlinks
  resolved
- `$LIB` / `${LIB}` — `lib64`, solder being x86-64 only

`$PLATFORM` is deliberately *not* substituted: it stands for whatever the
loader makes of the CPU the merged binary eventually runs on, which is not
knowable at merge time. An entry containing it is skipped with a warning, the
same way the loader skips it when it has no platform string.

`/etc/ld.so.cache` is filtered the way the loader filters it: only x86-64
`libc6` entries are considered, so the i386 or x32 build of a soname is never
picked, and a `glibc-hwcaps` variant loses to the baseline library — whether
the machine that will run the merged executable implements the instructions
that variant was built for is not knowable from here.

### Dependencies recorded as a path

A `DT_NEEDED` entry containing a slash — what the linker writes when the
library it was handed has no `DT_SONAME` — names a file rather than a soname,
and the loader opens it directly instead of searching for it. `solder` does the
same: none of the directories above are consulted for such an entry, it is only
expanded for dynamic string tokens (`$ORIGIN` here being the directory of the
object that declared the dependency) and used as given.

A *relative* path entry is rejected with an error. The loader resolves it
against the working directory of the running process, so which file it names is
not something the merge can know; merging whatever `solder`'s own working
directory happens to point at would be a guess. Use `-m` to merge the other
libraries and leave that one dynamic, or relink against a soname.

## How It Works

- Parses the executable's dynamic section to identify imported symbols
- Resolves which shared libraries provide those symbols (see
  [Library resolution](#library-resolution))
- Extracts the minimal set of code/data needed
  - Uses symbolic execution to identify jump tables in .rodata
- Applies relocations and creates trampolines for any remaining external calls
- Appends new `PT_LOAD` segments containing the merged code: read-execute for
  the code and trampolines, read-only for the constants, read-write for the
  data and the slots the dynamic loader fills in, read-only for the rebuilt
  symbol and relocation tables. Extracted read-only data only lands in the
  writable mapping when the dynamic loader still has to write to it — a
  pointer it rebases at startup, or a GOT slot it resolves
- Places those mappings' bytes at the file offset that gives them the same
  `p_vaddr - p_offset` the executable's own program header table has. The
  rebuilt program header table lives in the merged region, and a linker only
  ever emits that table in the first `PT_LOAD`, so tools that rewrite it —
  `patchelf` among them — read its difference as the one that holds for the
  start of the file. The merged region therefore starts past the end of the
  memory image in the file as well as in memory, which leaves the executable's
  `.bss` worth of unmapped zero padding in between
- Patches GOT entries to point directly to the merged symbols
- Neutralizes the merged symbols' own relocations so the loader leaves those
  slots alone: their `R_X86_64_JUMP_SLOT` entries become `R_X86_64_NONE`, and
  eager binding is forced (`DF_BIND_NOW` in `DT_FLAGS`, unless the executable
  already asked for it) because glibc's lazy PLT path rejects a type-0
  relocation outright — "unexpected PLT reloc type 0x00" — while its eager path
  treats it as the no-op it is. A merged binary therefore always binds eagerly,
  even if the original did not
- Removes the merged libraries from `DT_NEEDED` along with the
  `.gnu.version_r` requirements recorded against them — a version requirement
  naming a library that is no longer there aborts the loader on
  `Assertion 'needed != NULL' failed` — and moves onto the executable any
  `DT_NEEDED` of theirs that still provides a symbol the extracted code calls
  (see [Inherited dependencies](#inherited-dependencies))
- Carries the merged libraries' constructors and destructors onto the
  executable's `DT_PREINIT_ARRAY` and `DT_FINI_ARRAY` (see
  [Constructors and destructors](#constructors-and-destructors))
- Rewrites the section header table so it describes the result: the headers of
  the rebuilt `.dynsym`/`.dynstr`/`.gnu.version`/`.rela.dyn` are repointed at
  the copies the loader now reads, and `.solder.text`/`.solder.rodata`/
  `.solder.data` are added over the new mappings. `readelf`, `nm` and `gdb` read
  section headers rather than `PT_DYNAMIC`, so without this the merged binary
  still looks exactly like the input to all of them

## Limitations

- x86_64 only
- We can't merge `dlopen` libraries
- Extracted code may not contain relocations that need the library's own GOT
  (`R_X86_64_GOTPCREL` and friends); `solder` refuses the merge rather than
  producing a broken binary
- A copy-relocated data symbol (`R_X86_64_COPY`) coming from a library we're
  removing has to be zero-initialized, since its initial value currently can't
  be carried over
- We can't merge a library that uses thread-local storage, or one that defines
  an ifunc that extracted code reaches. Both are dynamic relocations whose slot
  is not an address — a TLS slot holds a module id or an offset from the thread
  pointer, and an `R_X86_64_IRELATIVE` slot holds the address of a resolver
  only `ld.so` can call — so there is nothing the merge can write into them.
  `solder` refuses the merge when one turns up inside extracted code or data
- Merged code carries no unwind information. A library's `.eh_frame` is read
  during extraction — it is how a function's exact bounds are recovered when
  the symbol table records no size for it — but none of it is written back
  out. `.eh_frame_hdr` and `PT_GNU_EH_FRAME` come through the merge byte for
  byte, still describing the executable's own code and nothing else, so no FDE
  covers `.solder.text`: merging `libpcre2-8.so.0` into `test/grep` leaves 28K
  of `libpcre2`'s `.eh_frame` behind. Anything that walks the stack through
  `_Unwind_*` therefore gives up at the first merged frame — glibc's
  `backtrace()` truncates there, a C++ exception propagating out of merged
  code gets `_URC_FATAL_PHASE1_ERROR` and `std::terminate`, and a
  `pthread_cancel` forced unwind cannot pass it. `gdb` is reduced to guessing
  its way through that code from the prologues. Don't merge a library the
  program unwinds through
- Merged code carries no symbols either. Nothing names the extracted functions
  in any symbol table, so a debugger or profiler sees `.solder.text` as one
  unnamed blob. The names the executable *imported* from the merged library do
  stay behind in `.dynsym`, as undefined entries that no relocation refers to
  any more, so `nm -D` on a merged binary still lists exactly the symbols that
  were merged in as undefined. That part is cosmetic rather than a load
  failure — their GOT slots are pre-filled and their relocations neutralized,
  so nothing asks the loader to resolve them — but it does mean the symbol
  tables are not a way to tell whether a merge worked. Read the
  `.solder.*` section headers, or `DT_NEEDED`, instead
