//! End-to-end runs of the `solder` binary over the committed fixtures.
//!
//! The unit tests reach into one stage at a time; these drive the whole thing
//! the way a user does — `solder <exe> -L test/libs` — and check the report it
//! prints against what actually came out the other end. A report that agrees
//! with itself is worth nothing: the point is that the `DT_NEEDED` lines match
//! the `DT_NEEDED` of the merged file, and that the size line matches the file
//! on disk.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Copy `fixture(name)` into `dir` and hand back the copy.
///
/// The fixtures are merged into rather than read: solder rewrites the
/// executable in place and keeps no backup, so pointing it at the committed
/// file would destroy it.
fn seed(dir: &Path, name: &str) -> PathBuf {
    let exe = dir.join(Path::new(name).file_name().expect("fixture file name"));
    std::fs::copy(fixture(name), &exe).expect("copy the fixture");
    exe
}

fn solder(args: &[&std::ffi::OsStr]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_solder"))
        .args(args)
        .output()
        .expect("run solder");
    assert!(
        output.status.success(),
        "solder {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Merge every mergeable library of `exe` out of `test/libs`, returning stdout.
fn merge(exe: &Path, extra: &[&str]) -> String {
    let libs = fixture("test/libs");
    let mut args: Vec<&std::ffi::OsStr> = vec![exe.as_ref(), "-L".as_ref(), libs.as_ref()];
    args.extend(extra.iter().map(|a| a.as_ref() as &std::ffi::OsStr));
    String::from_utf8(solder(&args).stdout).expect("stdout is UTF-8")
}

/// The `DT_NEEDED` entries of an ELF file, in order.
fn dt_needed(path: &Path) -> Vec<String> {
    let bytes = std::fs::read(path).expect("read the ELF file");
    goblin::elf::Elf::parse(&bytes)
        .expect("parse the ELF file")
        .libraries
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

/// The comma-separated list the report prints after `label`, or `None` when the
/// report has no such line.
fn reported_list<'r>(report: &'r str, label: &str) -> Option<Vec<&'r str>> {
    report
        .lines()
        .find_map(|line| line.trim().strip_prefix(label))
        .map(|list| list.trim().split(", ").collect())
}

/// `solder <exe>` used to print nothing whatsoever on success: both the plan
/// and the "merge complete" line went through `info!`, which the default `warn`
/// filter drops. The only way to find out what had happened to the executable
/// was a second run with `--dry-run`, or `readelf -d` on the output.
#[test]
fn a_merge_reports_the_libraries_it_absorbed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let exe = seed(dir.path(), "test/grep");
    let before = dt_needed(&exe);
    assert!(before.contains(&"libpcre2-8.so.0".to_owned()), "{before:?}");

    let report = merge(&exe, &[]);

    assert!(
        report.starts_with(&format!("Merged into {}\n", exe.display())),
        "{report}"
    );
    assert_eq!(
        reported_list(&report, "DT_NEEDED entries removed:"),
        Some(vec!["libpcre2-8.so.0"]),
        "{report}"
    );
    // What the report claims, against what the loader will now read.
    assert_eq!(
        reported_list(&report, "DT_NEEDED entries kept:"),
        Some(dt_needed(&exe).iter().map(String::as_str).collect()),
        "{report}"
    );
    assert!(
        !dt_needed(&exe).contains(&"libpcre2-8.so.0".to_owned()),
        "the absorbed soname is still in DT_NEEDED"
    );
}

/// The merge is not only subtractive: a dependency of an absorbed library that
/// still provides a symbol the extracted code calls moves onto the
/// executable's own `DT_NEEDED`. `libcrypto.so.3` leaves `test/md5sum` and
/// `libz.so.1` and `libzstd.so.1` arrive in its place — which a resolved
/// dependency used to announce with nothing louder than a `debug!`, from a
/// tool whose purpose is removing runtime dependencies.
#[test]
fn a_merge_reports_the_dependencies_it_inherited() {
    let dir = tempfile::tempdir().expect("temp dir");
    let exe = seed(dir.path(), "test/md5sum");

    let report = merge(&exe, &[]);

    let inherited = reported_list(
        &report,
        "DT_NEEDED entries inherited from the merged libraries:",
    )
    .unwrap_or_else(|| panic!("no inherited line in the report:\n{report}"));
    assert_eq!(inherited, vec!["libz.so.1", "libzstd.so.1"], "{report}");

    let needed = dt_needed(&exe);
    for soname in inherited {
        assert!(
            needed.contains(&soname.to_owned()),
            "the report claims {soname} was inherited, but DT_NEEDED is {needed:?}"
        );
    }
}

/// Merging multiplies the size of the executable, so the report says by how
/// much — and the numbers are the file's, not the plan's estimate of it.
#[test]
fn a_merge_reports_the_size_it_cost() {
    let dir = tempfile::tempdir().expect("temp dir");
    let exe = seed(dir.path(), "test/grep");
    let before = std::fs::metadata(&exe).expect("stat the input").len();

    let report = merge(&exe, &[]);

    let after = std::fs::metadata(&exe).expect("stat the output").len();
    assert!(after > before, "{before} -> {after}");
    assert!(
        report.contains(&format!("size: {before} bytes -> {after} bytes")),
        "{report}"
    );
}

/// `--dry-run` reports the same plan and writes nothing.
#[test]
fn a_dry_run_reports_the_plan_and_leaves_the_executable_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let exe = seed(dir.path(), "test/grep");
    let original = std::fs::read(&exe).expect("read the input");

    let report = merge(&exe, &["--dry-run"]);

    assert!(
        report.starts_with(&format!("Merge plan for {}\n", exe.display())),
        "{report}"
    );
    assert_eq!(
        reported_list(&report, "DT_NEEDED entries removed:"),
        Some(vec!["libpcre2-8.so.0"]),
        "{report}"
    );
    assert!(
        report.ends_with(&format!("Dry run: {} left unchanged\n", exe.display())),
        "{report}"
    );
    assert_eq!(
        std::fs::read(&exe).expect("read the untouched input"),
        original,
        "--dry-run rewrote the executable"
    );
}

/// The libraries `test/libs` holds are not installed on an ordinary host, so
/// every fixture needs `-L` to resolve them. A dependency solder cannot find
/// is not a refusal: the entry stays in `DT_NEEDED`, nothing is merged out of
/// it, and — with `test/grep` importing from that one library only — there is
/// nothing left to merge at all, so the executable has to come out of the run
/// byte-for-byte as it went in.
#[test]
fn a_dt_needed_entry_that_cannot_be_found_is_left_in_place() {
    let dir = tempfile::tempdir().expect("temp dir");
    let exe = seed(dir.path(), "test/grep");
    let original = std::fs::read(&exe).expect("read the input");

    let output = Command::new(env!("CARGO_BIN_EXE_solder"))
        .arg(&exe)
        .arg("-L")
        .arg(dir.path())
        .output()
        .expect("run solder");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a dependency that cannot be found is skipped, not fatal: {stderr}"
    );
    assert!(stderr.contains("libpcre2-8.so.0"), "{stderr}");
    assert!(
        dt_needed(&exe).contains(&"libpcre2-8.so.0".to_owned()),
        "the soname nothing was merged out of left DT_NEEDED"
    );
    assert_eq!(
        std::fs::read(&exe).expect("read the untouched input"),
        original,
        "a run that merged nothing rewrote the executable"
    );
}
