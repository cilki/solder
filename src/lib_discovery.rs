use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Library names (or prefixes) that must never be merged — they are part of
/// glibc / the kernel ABI and must remain as dynamic dependencies.
const NEVER_MERGE_PREFIXES: &[&str] = &[
    "ld-linux",
    "ld-musl",
    "linux-vdso",
    "linux-gate",
    "libc.so",
    "libm.so",
    "librt.so",
    "libpthread",
    "libdl.so",
    "libresolv",
    "libnss_",
    "libgcc_s.so",
];

/// The file-name part of a `DT_NEEDED` entry.
///
/// A dependency is usually recorded as a bare soname, but it may also be
/// recorded as a path — `/opt/app/lib/libfoo.so`, `$ORIGIN/../lib/libfoo.so`,
/// `sub/libfoo.so` — which is what the linker writes when the library it was
/// given has no `DT_SONAME`. Everything that reasons about a dependency *by
/// name* has to look at the last component, or a path-shaped entry slips past
/// it: `"/usr/lib64/libc.so.6".starts_with("libc.so")` is false, which is
/// enough to walk a path-shaped entry straight through the never-merge list.
pub fn soname_base(needed: &str) -> &str {
    needed.rsplit('/').next().unwrap_or(needed)
}

/// Returns true if the given `DT_NEEDED` entry names a library that must never
/// be merged.
pub fn is_excluded(needed: &str) -> bool {
    let name = soname_base(needed);
    NEVER_MERGE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Expand the dynamic string tokens `ld.so` substitutes into a `DT_RPATH` or
/// `DT_RUNPATH` entry before using it as a search directory, in both the
/// `$TOKEN` and `${TOKEN}` spellings.
///
/// `origin` is the directory holding the object the entry came from, with
/// symlinks resolved — what `$ORIGIN` means to the loader.
///
/// Returns `None` for an entry carrying a token that cannot be resolved here.
/// The loader skips such an entry as well, and searching a directory named
/// literally `$PLATFORM` would only mask the fact that solder and the loader
/// are looking in different places.
pub fn expand_dynamic_tokens(entry: &str, origin: &Path) -> Option<PathBuf> {
    let mut out = String::with_capacity(entry.len());
    let mut rest = entry;

    while let Some(dollar) = rest.find('$') {
        out.push_str(&rest[..dollar]);
        let after = &rest[dollar + 1..];
        let (token, tail) = match after.strip_prefix('{') {
            // `${TOKEN}`: without a closing brace there is no token to expand.
            Some(braced) => braced.split_once('}')?,
            // `$TOKEN` runs up to the first character that cannot be part of
            // a name — usually the `/` starting the rest of the path.
            None => {
                let end = after
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(after.len());
                after.split_at(end)
            }
        };

        match token {
            "ORIGIN" => out.push_str(origin.to_str()?),
            // ld.so(8): `lib` or `lib64` according to the architecture, and
            // solder only ever merges x86-64 objects.
            "LIB" => out.push_str("lib64"),
            // `$PLATFORM` names whatever the loader makes of the CPU it finds
            // itself on (on x86-64: `haswell`, `xeon_phi`, or nothing at all),
            // so the directory it would pick is not knowable from here.
            _ => return None,
        }
        rest = tail;
    }

    out.push_str(rest);
    Some(PathBuf::from(out))
}

/// Resolve a `DT_NEEDED` entry (e.g. "libz.so.1") to an absolute path on disk.
///
/// An entry containing a slash names a file rather than a soname and is
/// resolved by [`resolve_path_entry`] without consulting the search path at
/// all, exactly as ld.so does. `origin` is the directory holding the object the
/// entry came from, with symlinks resolved — what `$ORIGIN` means to the
/// loader.
///
/// For a bare soname the search order mirrors the Linux dynamic linker:
///   1. Caller-supplied `rpath` entries. The caller appends `$SYSROOT/lib` and
///      any `-L` directories here, so those are searched after the
///      executable's own `DT_RPATH` but ahead of `LD_LIBRARY_PATH`.
///   2. `LD_LIBRARY_PATH` directories (from the solder process environment)
///   3. Caller-supplied `runpath` entries
///   4. `/etc/ld.so.cache`
///   5. Default paths: /lib64, /usr/lib64, /lib, /usr/lib,
///      /lib/x86_64-linux-gnu, /usr/lib/x86_64-linux-gnu
pub fn resolve_library(
    soname: &str,
    rpath: &[PathBuf],
    runpath: &[PathBuf],
    ldso_cache: &LdsoCache,
    origin: &Path,
) -> Result<PathBuf> {
    // 0. Not a soname at all, but a path.
    if soname.contains('/') {
        return resolve_path_entry(soname, origin);
    }

    // 1. RPATH
    for dir in rpath {
        let candidate = dir.join(soname);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // 2. LD_LIBRARY_PATH
    if let Ok(llp) = std::env::var("LD_LIBRARY_PATH") {
        for dir in llp.split(':').filter(|s| !s.is_empty()) {
            let candidate = Path::new(dir).join(soname);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // 3. RUNPATH
    for dir in runpath {
        let candidate = dir.join(soname);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // 4. ld.so.cache
    if let Some(path) = ldso_cache.lookup(soname)
        && path.exists()
    {
        return Ok(path.to_owned());
    }

    // 5. Default paths
    for dir in &[
        "/lib64",
        "/usr/lib64",
        "/lib",
        "/usr/lib",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
    ] {
        let candidate = Path::new(dir).join(soname);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("cannot find shared library '{soname}' — try -L to add a search path")
}

/// Resolve a `DT_NEEDED` entry that names a path instead of a soname.
///
/// glibc's `_dl_map_object` branches on `strchr (name, '/')`: an entry with a
/// slash in it is expanded for dynamic string tokens and opened directly, and
/// no search directory is ever consulted for it. Joining such an entry onto the
/// search path instead — which is what `dir.join(entry)` did for every entry —
/// is wrong twice over:
///
///   * `..` in the entry walks out of the directory it is joined to, so an
///     entry like `../../../usr/lib64/libfoo.so` escapes `$SYSROOT/lib` or a
///     `-L` directory and merges host code into a sysroot build; an absolute
///     entry discards the search directory outright, since `Path::join` with
///     an absolute path replaces the whole base.
///   * even when it stays inside, `<searchdir>/<entry>` is a different file
///     from the one ld.so will open, so the merge pulls in code the executable
///     never runs.
fn resolve_path_entry(needed: &str, origin: &Path) -> Result<PathBuf> {
    let path = expand_dynamic_tokens(needed, origin).with_context(|| {
        format!("DT_NEEDED '{needed}' names a path whose tokens cannot be expanded here")
    })?;

    // ld.so resolves a relative entry against the working directory of the
    // *running process*, which is not knowable when the merge happens. Merging
    // whichever file solder's own working directory points at would be a guess
    // at which library the executable loads.
    if !path.is_absolute() {
        bail!(
            "DT_NEEDED '{needed}' is a relative path, which ld.so resolves against the \
             working directory of the running process — solder cannot tell which file that \
             will be. Exclude this library from the merge, or relink the executable against \
             a soname or an absolute (or $ORIGIN-relative) path."
        );
    }
    if !path.exists() {
        bail!(
            "cannot find shared library '{needed}': {} does not exist",
            path.display()
        );
    }
    Ok(path)
}

/// `CACHEMAGIC_NEW CACHE_VERSION` — the magic of `struct cache_file_new`.
const MAGIC_NEW: &[u8] = b"glibc-ld.so.cache1.1";
/// `CACHEMAGIC` — the magic of the original `struct cache_file`.
const MAGIC_OLD: &[u8] = b"ld.so-1.7.0";
/// `sizeof (struct cache_file_new)`, which glibc static-asserts to be 48:
/// magic(17) + version(3) + nlibs(4) + len_strings(4) + flags(1) +
/// padding(3) + extension_offset(4) + unused(12).
const NEW_HEADER_SIZE: usize = 48;
/// `sizeof (struct file_entry_new)`: flags(4) + key(4) + value(4) +
/// osversion_unused(4) + hwcap(8).
const NEW_ENTRY_SIZE: usize = 24;
/// `sizeof (struct cache_file)`: magic(11) + a padding byte + nlibs(4).
const OLD_HEADER_SIZE: usize = 16;
/// `sizeof (struct file_entry)`: flags(4) + key(4) + value(4).
const OLD_ENTRY_SIZE: usize = 12;
/// `DL_CACHE_HWCAP_EXTENSION`: set in an entry's `hwcap` when the low bits are
/// an index into the cache's `glibc-hwcaps` subdirectory list rather than a
/// hwcap bitmask.
const DL_CACHE_HWCAP_EXTENSION: u64 = 1 << 62;
/// `_DL_CACHE_DEFAULT_ID` from glibc's `sysdeps/x86_64/dl-cache.h`:
/// `FLAG_X8664_LIB64 | FLAG_ELF_LIBC6`. On x86-64 `_dl_cache_check_flags`
/// accepts this value and nothing else, so an entry with any other `flags` is
/// one the dynamic linker would never load.
const FLAG_X8664_LIBC6: u32 = 0x0303;

/// Parser for the glibc `ld.so.cache` binary format, after the structures in
/// glibc's `sysdeps/generic/dl-cache.h`.
///
/// Two on-disk layouts exist and both are in the wild:
///
///   * the new format alone — a `struct cache_file_new` at offset 0, which is
///     what `ldconfig` has written by default since glibc 2.32;
///   * the compatibility layout older `ldconfig` versions wrote — a
///     `struct cache_file` (magic `ld.so-1.7.0`) with 12-byte entries,
///     followed by an 8-byte-aligned `struct cache_file_new` repeating the
///     same libraries, hidden where the old format's string table starts.
pub struct LdsoCache {
    map: HashMap<String, PathBuf>,
}

impl LdsoCache {
    /// Load from the default path `/etc/ld.so.cache`, or return an empty cache
    /// if the file is absent or cannot be parsed (non-fatal — fallback to
    /// filesystem search still works).
    pub fn load() -> Self {
        Self::load_from(Path::new("/etc/ld.so.cache")).unwrap_or_else(|_| Self {
            map: HashMap::new(),
        })
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&data).with_context(|| format!("parsing {}", path.display()))
    }

    fn parse(data: &[u8]) -> Result<Self> {
        if data.starts_with(MAGIC_NEW) {
            return Self::parse_new(data, 0);
        }
        if !data.starts_with(MAGIC_OLD) {
            bail!("unrecognized ld.so.cache format");
        }

        // Old header, then `nlibs` 12-byte entries, then the string table —
        // whose first 8-byte-aligned bytes hold a complete new-format header
        // when `ldconfig` wrote both formats. Prefer that one: it is the one
        // the dynamic linker reads, and it carries the hwcap information the
        // old entries cannot express.
        let nlibs = read_u32(data, 12)? as usize;
        let room = data.len().saturating_sub(OLD_HEADER_SIZE) / OLD_ENTRY_SIZE;
        if nlibs > room {
            bail!("ld.so.cache declares {nlibs} entries but the file holds at most {room}");
        }
        let strings_start = OLD_HEADER_SIZE + nlibs * OLD_ENTRY_SIZE;
        let embedded = strings_start.next_multiple_of(8);
        if data.len() > embedded + NEW_HEADER_SIZE && data[embedded..].starts_with(MAGIC_NEW) {
            return Self::parse_new(data, embedded);
        }

        Self::parse_old(data, nlibs, strings_start)
    }

    /// Parse the `struct cache_file_new` whose header starts at `base`.
    ///
    /// String table indices in this format are relative to `base` rather than
    /// to the start of the string table — glibc reads them off
    /// `cache_data = (const char *) cache_new`.
    fn parse_new(data: &[u8], base: usize) -> Result<Self> {
        if data.len() < base + NEW_HEADER_SIZE {
            bail!("ld.so.cache is truncated inside its header");
        }

        // The low two bits of `flags` record the endianness `ldconfig` wrote
        // the file with (0 = an old ldconfig left it unset). Every offset in a
        // cache from the other endianness is byte-swapped, so there is nothing
        // to usefully read out of one.
        const ENDIAN_MASK: u8 = 3;
        const ENDIAN_LITTLE: u8 = 2;
        let endian = data[base + 28] & ENDIAN_MASK;
        if endian != 0 && endian != ENDIAN_LITTLE {
            bail!("ld.so.cache was written for a big-endian machine");
        }

        let nlibs = read_u32(data, base + 20)? as usize;
        let entries_start = base + NEW_HEADER_SIZE;
        let room = data.len().saturating_sub(entries_start) / NEW_ENTRY_SIZE;
        if nlibs > room {
            bail!("ld.so.cache declares {nlibs} entries but the file holds at most {room}");
        }

        let mut map = HashMap::with_capacity(nlibs);
        for i in 0..nlibs {
            let entry = entries_start + i * NEW_ENTRY_SIZE;
            let flags = read_u32(data, entry)?;
            let hwcap = read_u64(data, entry + 16)?;

            // Skip the entries ld.so itself would pass over on this machine:
            //
            //   * anything but an x86-64 libc6 library. A multilib cache also
            //     lists the i386 and x32 builds of the same soname, and
            //     merging a 32-bit library into a 64-bit executable is not a
            //     thing.
            //   * a `glibc-hwcaps` entry, whose path is only loadable on a CPU
            //     with capabilities we cannot evaluate from here. `ldconfig`
            //     sorts these ahead of the baseline entry for the same soname,
            //     so after skipping them the first entry left is the one ld.so
            //     falls back to.
            if flags != FLAG_X8664_LIBC6 || hwcap & DL_CACHE_HWCAP_EXTENSION != 0 {
                continue;
            }

            let soname = read_cstr(data, base + read_u32(data, entry + 4)? as usize)?;
            let path = read_cstr(data, base + read_u32(data, entry + 8)? as usize)?;
            map.entry(soname.to_owned())
                .or_insert_with(|| PathBuf::from(path));
        }

        Ok(Self { map })
    }

    /// Parse the `nlibs` `struct file_entry`s of the original format, whose
    /// string table indices are relative to the end of the entry array.
    fn parse_old(data: &[u8], nlibs: usize, strings_start: usize) -> Result<Self> {
        let mut map = HashMap::with_capacity(nlibs);
        for i in 0..nlibs {
            let entry = OLD_HEADER_SIZE + i * OLD_ENTRY_SIZE;
            if read_u32(data, entry)? != FLAG_X8664_LIBC6 {
                continue;
            }
            let soname = read_cstr(data, strings_start + read_u32(data, entry + 4)? as usize)?;
            let path = read_cstr(data, strings_start + read_u32(data, entry + 8)? as usize)?;
            map.entry(soname.to_owned())
                .or_insert_with(|| PathBuf::from(path));
        }

        Ok(Self { map })
    }

    pub fn lookup(&self, soname: &str) -> Option<&Path> {
        self.map.get(soname).map(PathBuf::as_path)
    }
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .with_context(|| format!("ld.so.cache: u32 at offset {offset} is past the end"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .with_context(|| format!("ld.so.cache: u64 at offset {offset} is past the end"))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_cstr(data: &[u8], offset: usize) -> Result<&str> {
    if offset >= data.len() {
        bail!("ld.so.cache string offset {offset} out of bounds");
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    std::str::from_utf8(&data[offset..end])
        .with_context(|| format!("non-UTF8 string at offset {offset}"))
}

#[cfg(test)]
mod resolution_tests {
    use super::*;

    /// A cache with nothing in it, so resolution depends only on the paths.
    fn empty_cache() -> LdsoCache {
        LdsoCache {
            map: HashMap::new(),
        }
    }

    #[test]
    fn origin_expands_to_the_directory_holding_the_object() {
        assert_eq!(
            expand_dynamic_tokens("$ORIGIN/../lib", Path::new("/opt/app/bin")),
            Some(PathBuf::from("/opt/app/bin/../lib"))
        );
    }

    #[test]
    fn braced_tokens_are_expanded_too() {
        assert_eq!(
            expand_dynamic_tokens("${ORIGIN}/libs", Path::new("/opt/app")),
            Some(PathBuf::from("/opt/app/libs"))
        );
    }

    #[test]
    fn several_tokens_in_one_entry_are_all_expanded() {
        assert_eq!(
            expand_dynamic_tokens("$ORIGIN/../$LIB/plugins", Path::new("/opt/app/bin")),
            Some(PathBuf::from("/opt/app/bin/../lib64/plugins"))
        );
    }

    #[test]
    fn lib_expands_to_the_x86_64_library_directory() {
        assert_eq!(
            expand_dynamic_tokens("/usr/$LIB", Path::new("/opt/app")),
            Some(PathBuf::from("/usr/lib64"))
        );
    }

    #[test]
    fn an_entry_without_tokens_is_left_alone() {
        assert_eq!(
            expand_dynamic_tokens("/usr/local/lib", Path::new("/opt/app")),
            Some(PathBuf::from("/usr/local/lib"))
        );
    }

    #[test]
    fn an_entry_with_an_unresolvable_token_is_dropped() {
        // `$PLATFORM` depends on the CPU the merged binary ends up running on,
        // and an unterminated `${` is not a token at all. Either way, guessing
        // a directory is worse than leaving the entry out of the search.
        for entry in ["/usr/lib/$PLATFORM", "${ORIGIN/lib", "$ORIGIN$"] {
            assert_eq!(
                expand_dynamic_tokens(entry, Path::new("/opt/app")),
                None,
                "{entry} should not have expanded"
            );
        }
    }

    #[test]
    fn an_expanded_origin_entry_resolves_a_bundled_library() {
        // The case this is all for: an executable linked with
        // `-Wl,-rpath,'$ORIGIN/libs'` ships its libraries next to itself, and
        // the unexpanded entry names a directory that never exists.
        let root = tempfile::tempdir().expect("tempdir");
        let libs = root.path().join("libs");
        std::fs::create_dir(&libs).expect("libs dir");
        std::fs::write(libs.join("libfoo.so.1"), b"").expect("bundled library");

        let origin = root.path();
        let raw = "$ORIGIN/libs";
        assert!(
            resolve_library(
                "libfoo.so.1",
                &[PathBuf::from(raw)],
                &[],
                &empty_cache(),
                origin
            )
            .is_err(),
            "an unexpanded $ORIGIN entry cannot name a real directory"
        );

        let expanded = expand_dynamic_tokens(raw, origin).expect("expands");
        assert_eq!(
            resolve_library("libfoo.so.1", &[expanded], &[], &empty_cache(), origin).ok(),
            Some(libs.join("libfoo.so.1"))
        );
    }

    #[test]
    fn the_never_merge_list_is_matched_against_the_last_path_component() {
        // A library linked without a DT_SONAME is recorded in DT_NEEDED as the
        // path the linker was handed. Matching the never-merge prefixes against
        // the whole entry let such a spelling of glibc through the list, and
        // solder would go on to statically merge libc into the executable.
        for entry in [
            "/usr/lib64/libc.so.6",
            "../../lib/libc.so.6",
            "./libpthread.so.0",
            "$ORIGIN/../lib/ld-linux-x86-64.so.2",
            "lib/libgcc_s.so.1",
        ] {
            assert!(is_excluded(entry), "{entry} must stay a dynamic dependency");
        }

        assert!(is_excluded("libc.so.6"), "a bare soname still matches");
        assert!(!is_excluded("/opt/app/lib/libfoo.so.1"));
        assert!(
            !is_excluded("/libc.so.6-not-really/libfoo.so"),
            "a directory named after an excluded library does not exclude the file in it"
        );
    }

    /// A tree with the same library name present both inside and outside a
    /// search directory, so a resolution that escapes the search directory is
    /// distinguishable from one that stays inside it.
    fn decoy_tree() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        for dir in ["sysroot/lib/sub", "elsewhere/sub"] {
            std::fs::create_dir_all(root.path().join(dir)).expect("dir");
            std::fs::write(root.path().join(dir).join("libfoo.so.1"), b"").expect("library");
        }
        root
    }

    #[test]
    fn a_relative_path_entry_does_not_walk_out_of_a_search_directory() {
        // ld.so opens a slash-bearing DT_NEEDED entry directly, relative to the
        // working directory of the running process; it never joins it onto a
        // search directory. Joining it meant `..` escaped `$SYSROOT/lib` (or a
        // `-L` directory) and solder merged a library from the host that the
        // executable will never load.
        let root = decoy_tree();
        let sysroot_lib = root.path().join("sysroot/lib");
        let escaped = root.path().join("elsewhere/sub/libfoo.so.1");
        assert!(
            sysroot_lib.join("../../elsewhere/sub/libfoo.so.1").exists(),
            "the traversal target has to exist for this to be a meaningful test"
        );

        let resolved = resolve_library(
            "../../elsewhere/sub/libfoo.so.1",
            &[sysroot_lib],
            &[],
            &empty_cache(),
            root.path(),
        );
        assert_ne!(
            resolved.as_deref().ok(),
            Some(escaped.as_path()),
            "a relative entry must not be resolved through the search path"
        );
        let err = format!("{:#}", resolved.expect_err("relative entry"));
        assert!(err.contains("relative path"), "{err}");
    }

    #[test]
    fn an_absolute_path_entry_ignores_the_search_path() {
        // `Path::join` with an absolute path throws the base away, so the old
        // search-path walk resolved an absolute entry to itself as a side
        // effect of the first search directory that happened to be non-empty.
        // Now it is deliberate — and it no longer depends on there being one.
        let root = decoy_tree();
        let wanted = root.path().join("elsewhere/sub/libfoo.so.1");
        assert_eq!(
            resolve_library(
                wanted.to_str().expect("utf8"),
                &[],
                &[],
                &empty_cache(),
                root.path()
            )
            .ok(),
            Some(wanted)
        );
    }

    #[test]
    fn an_origin_relative_path_entry_resolves_against_the_object() {
        // The useful shape of a path-valued DT_NEEDED: a bundled library
        // referenced from the executable's own directory.
        let root = decoy_tree();
        let origin = root.path().join("sysroot");
        assert_eq!(
            resolve_library(
                "$ORIGIN/lib/sub/libfoo.so.1",
                &[],
                &[],
                &empty_cache(),
                &origin
            )
            .ok(),
            Some(origin.join("lib/sub/libfoo.so.1"))
        );
    }

    #[test]
    fn a_path_entry_that_does_not_exist_names_the_path_it_looked_at() {
        let root = decoy_tree();
        let missing = root.path().join("sysroot/lib/sub/libmissing.so.1");
        let err = format!(
            "{:#}",
            resolve_library(
                "$ORIGIN/sub/libmissing.so.1",
                &[root.path().join("sysroot/lib/sub")],
                &[],
                &empty_cache(),
                &root.path().join("sysroot/lib"),
            )
            .expect_err("the library is not there")
        );
        assert!(err.contains(&missing.display().to_string()), "{err}");
    }

    #[test]
    fn rpath_is_ignored_when_runpath_is_present() {
        use crate::symbol_analysis::DynamicInfo;

        let rpath = vec![PathBuf::from("/from/rpath")];
        let runpath = vec![PathBuf::from("/from/runpath")];

        let both = DynamicInfo {
            needed: Vec::new(),
            rpath: rpath.clone(),
            runpath,
            origin: PathBuf::from("/opt/app"),
        };
        assert!(
            both.search_rpath().is_empty(),
            "ld.so ignores DT_RPATH on an object that also has DT_RUNPATH"
        );

        let rpath_only = DynamicInfo {
            needed: Vec::new(),
            rpath: rpath.clone(),
            runpath: Vec::new(),
            origin: PathBuf::from("/opt/app"),
        };
        assert_eq!(rpath_only.search_rpath(), rpath.as_slice());
    }
}

#[cfg(test)]
mod ldso_cache_tests {
    use super::*;

    /// `(flags, hwcap, soname, path)` for one cache entry.
    type Entry<'a> = (u32, u64, &'a str, &'a str);

    const X8664: u32 = FLAG_X8664_LIBC6;
    /// `FLAG_ELF_LIBC6` with no architecture bits — a 32-bit i386 library.
    const I386: u32 = 0x0003;

    /// Lay out a new-format cache: `struct cache_file_new`, the entry array,
    /// then the string table. Entry string indices are relative to the start
    /// of the header, which is what makes this blob embeddable unchanged in
    /// the compatibility layout below.
    fn new_format(entries: &[Entry<'_>]) -> Vec<u8> {
        let strings_at = NEW_HEADER_SIZE + entries.len() * NEW_ENTRY_SIZE;
        let mut strings: Vec<u8> = Vec::new();
        let intern = |s: &str, strings: &mut Vec<u8>| {
            let offset = strings_at + strings.len();
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            offset as u32
        };

        let mut table = Vec::new();
        for (flags, hwcap, soname, path) in entries {
            let key = intern(soname, &mut strings);
            let value = intern(path, &mut strings);
            table.extend_from_slice(&flags.to_le_bytes());
            table.extend_from_slice(&key.to_le_bytes());
            table.extend_from_slice(&value.to_le_bytes());
            table.extend_from_slice(&0u32.to_le_bytes()); // osversion_unused
            table.extend_from_slice(&hwcap.to_le_bytes());
        }

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC_NEW);
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes()); // nlibs
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes()); // len_strings
        out.push(2); // flags: little-endian
        out.extend_from_slice(&[0; 3]); // padding_unsed
        out.extend_from_slice(&0u32.to_le_bytes()); // extension_offset
        out.extend_from_slice(&[0; 12]); // unused[3]
        assert_eq!(out.len(), NEW_HEADER_SIZE);
        out.extend_from_slice(&table);
        out.extend_from_slice(&strings);
        out
    }

    /// Lay out the compatibility format: a `struct cache_file` whose string
    /// table begins with a complete `struct cache_file_new`. The old entries
    /// are left zeroed — once the new header is found nothing reads them, the
    /// same way glibc ignores them.
    fn combined(entries: &[Entry<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC_OLD);
        out.push(0); // padding before nlibs
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        out.resize(OLD_HEADER_SIZE + entries.len() * OLD_ENTRY_SIZE, 0);
        out.resize(out.len().next_multiple_of(8), 0); // ALIGN_CACHE
        out.extend_from_slice(&new_format(entries));
        out
    }

    #[test]
    fn a_new_format_cache_resolves_a_soname() {
        let data = new_format(&[(X8664, 0, "libz.so.1", "/usr/lib64/libz.so.1")]);
        let cache = LdsoCache::parse(&data).expect("new-format cache");
        assert_eq!(
            cache.lookup("libz.so.1"),
            Some(Path::new("/usr/lib64/libz.so.1"))
        );
    }

    #[test]
    fn the_new_cache_embedded_in_the_legacy_layout_is_used() {
        let data = combined(&[(X8664, 0, "libz.so.1", "/usr/lib64/libz.so.1")]);
        let cache = LdsoCache::parse(&data).expect("combined cache");
        assert_eq!(
            cache.lookup("libz.so.1"),
            Some(Path::new("/usr/lib64/libz.so.1"))
        );
    }

    #[test]
    fn an_old_format_only_cache_still_parses() {
        // No embedded new header: entries and strings in the original layout.
        let soname = "libz.so.1";
        let path = "/usr/lib64/libz.so.1";
        let strings_start = OLD_HEADER_SIZE + OLD_ENTRY_SIZE;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC_OLD);
        out.push(0);
        out.extend_from_slice(&1u32.to_le_bytes()); // nlibs
        out.extend_from_slice(&X8664.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // key
        out.extend_from_slice(&((soname.len() + 1) as u32).to_le_bytes()); // value
        assert_eq!(out.len(), strings_start);
        out.extend_from_slice(soname.as_bytes());
        out.push(0);
        out.extend_from_slice(path.as_bytes());
        out.push(0);

        let cache = LdsoCache::parse(&out).expect("old-format cache");
        assert_eq!(cache.lookup(soname), Some(Path::new(path)));
    }

    #[test]
    fn a_hwcaps_entry_does_not_shadow_the_baseline_library() {
        let data = new_format(&[
            (
                X8664,
                DL_CACHE_HWCAP_EXTENSION | 1,
                "libfoo.so.1",
                "/usr/lib64/glibc-hwcaps/x86-64-v3/libfoo.so.1",
            ),
            (X8664, 0, "libfoo.so.1", "/usr/lib64/libfoo.so.1"),
        ]);
        let cache = LdsoCache::parse(&data).expect("cache with hwcaps entries");
        assert_eq!(
            cache.lookup("libfoo.so.1"),
            Some(Path::new("/usr/lib64/libfoo.so.1")),
            "a glibc-hwcaps path is only loadable on some CPUs"
        );
    }

    #[test]
    fn an_entry_for_another_abi_is_ignored() {
        let data = new_format(&[
            (I386, 0, "libbar.so.1", "/usr/lib/libbar.so.1"),
            (X8664, 0, "libbar.so.1", "/usr/lib64/libbar.so.1"),
        ]);
        let cache = LdsoCache::parse(&data).expect("multilib cache");
        assert_eq!(
            cache.lookup("libbar.so.1"),
            Some(Path::new("/usr/lib64/libbar.so.1")),
            "a 32-bit library cannot be merged into a 64-bit executable"
        );
    }

    #[test]
    fn a_cache_without_a_known_magic_is_rejected() {
        assert!(LdsoCache::parse(b"not a cache at all").is_err());
        assert!(LdsoCache::parse(&[]).is_err());
    }

    #[test]
    fn every_truncation_is_an_error_rather_than_a_panic() {
        for cache in [
            new_format(&[(X8664, 0, "libz.so.1", "/usr/lib64/libz.so.1")]),
            combined(&[(X8664, 0, "libz.so.1", "/usr/lib64/libz.so.1")]),
        ] {
            for len in 0..cache.len() {
                let _ = LdsoCache::parse(&cache[..len]);
            }
        }
    }

    #[test]
    fn an_entry_count_larger_than_the_file_is_rejected() {
        let mut data = new_format(&[(X8664, 0, "libz.so.1", "/usr/lib64/libz.so.1")]);
        data[20..24].copy_from_slice(&u32::MAX.to_le_bytes()); // nlibs
        assert!(LdsoCache::parse(&data).is_err());
    }
}
