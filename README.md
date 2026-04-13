# solder

Don't rebuild it, `solder` it!

**solder** is a post-link static merger for ELF executables. It extracts symbols
from shared libraries and fuses them directly into the executable, rendering the
libraries no longer needed at runtime.

## Partial static linking

When you need a partially static binary, not all build tools make this easy.
With `solder`, you don't need to recompile anything. Just give it your
executable and the shared objects you want to make static while leaving others
dynamically linked.

## How It Works

1. Parses the executable's dynamic section to identify imported symbols
2. Resolves which shared libraries provide those symbols (using `ld.so.cache`
   and library search paths)
3. Extracts the minimal set of code/data needed, including transitive
   dependencies
4. Applies relocations and creates trampolines for any remaining external calls
5. Appends a new `PT_LOAD` segment containing the merged code
6. Patches GOT entries to point directly to the merged symbols
7. Removes the merged libraries from `DT_NEEDED`

## Usage

```sh
# Merge all possible libraries into the executable (in-place)
solder ./myapp

# Merge only specific libraries by soname
solder ./myapp -m libfoo.so.1 -m libbar.so.2

# Add additional library search paths
solder ./myapp -L /opt/mylibs -L ./libs

# Preview what would be merged without writing output
solder ./myapp --dry-run

# Verbose output showing relocation details
solder ./myapp --verbose
```

### Options

| Option                      | Description                                                |
| --------------------------- | ---------------------------------------------------------- |
| `<INPUT>`                   | ELF executable to merge libraries into (modified in-place) |
| `-m, --merge <SONAME>`      | Merge only specific libraries (can be repeated)            |
| `-L, --library-path <PATH>` | Additional library search directories                      |
| `--dry-run`                 | Analyse and print the merge plan without writing output    |
| `--merge-base <HEX>`        | Override base virtual address for merged segment           |
| `-v, --verbose`             | Show verbose relocation details                            |

## Limitations

- **x86-64 Linux only** (for now)
- Libraries with `.init_array` / `.fini_array` (constructors/destructors) are
  not supported
- Some relocation types (GOT-relative) require recompilation with older
  toolchains or are not yet supported
- Thread-local storage (TLS) variables may not work correctly
- Symbol versioning is not fully handled
