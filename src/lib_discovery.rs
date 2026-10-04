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

/// Returns true if the given soname should never be merged.
pub fn is_excluded(soname: &str) -> bool {
    NEVER_MERGE_PREFIXES
        .iter()
        .any(|prefix| soname.starts_with(prefix))
}

/// Resolve a soname (e.g. "libz.so.1") to an absolute path on disk.
///
/// Search order mirrors the Linux dynamic linker:
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
) -> Result<PathBuf> {
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
