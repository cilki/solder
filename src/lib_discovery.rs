use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

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
///   1. Caller-supplied `rpath` entries
///   2. `LD_LIBRARY_PATH` directories (from the elfpack process environment)
///   3. Caller-supplied `runpath` entries
///   4. `/etc/ld.so.cache`
///   5. Default paths: /lib64, /usr/lib64, /lib, /usr/lib
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
    if let Some(path) = ldso_cache.lookup(soname) {
        if path.exists() {
            return Ok(path.to_owned());
        }
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

/// Minimal parser for the glibc `ld.so.cache` binary format (CACHE_MAGIC_NEW /
/// "glibc-ld.so.cache1.1").
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
        // New-format magic: "glibc-ld.so.cache1.1"
        const MAGIC_NEW: &[u8] = b"glibc-ld.so.cache1.1";
        if data.len() < MAGIC_NEW.len() || &data[..MAGIC_NEW.len()] != MAGIC_NEW {
            bail!("unrecognized ld.so.cache format");
        }

        // After magic (20 bytes), there are 5 unused u32 fields (20 bytes), then
        // u32 nlibs (number of entries).
        // Each entry is: u32 flags, u32 key_offset, u32 value_offset (all relative
        // to the start of the string table which begins right after the entry array).
        // Layout: magic(20) + unused(20) + nlibs(4) + entries(nlibs * 12) + strings(rest)
        const HEADER_SIZE: usize = 20 + 20;
        if data.len() < HEADER_SIZE + 4 {
            bail!("ld.so.cache too small");
        }

        let nlibs =
            u32::from_le_bytes(data[HEADER_SIZE..HEADER_SIZE + 4].try_into().unwrap()) as usize;
        let entries_start = HEADER_SIZE + 4;
        let entry_size = 12; // flags(4) + key(4) + value(4)
        let strings_start = entries_start + nlibs * entry_size;
        if data.len() < strings_start {
            bail!("ld.so.cache entries overflow file");
        }

        let mut map = HashMap::with_capacity(nlibs);
        for i in 0..nlibs {
            let off = entries_start + i * entry_size;
            // Skip flags (4 bytes)
            let key_off = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
            let val_off = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()) as usize;

            let key = read_cstr(data, strings_start + key_off)?;
            let val = read_cstr(data, strings_start + val_off)?;
            map.insert(key.to_owned(), PathBuf::from(val));
        }

        Ok(Self { map })
    }

    pub fn lookup(&self, soname: &str) -> Option<&Path> {
        self.map.get(soname).map(PathBuf::as_path)
    }
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
