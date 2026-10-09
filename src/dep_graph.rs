//! Dependency ordering for the libraries being merged.
//!
//! Libraries with constructors must have their init functions called in dependency order:
//! if library A depends on library B, B's constructors must run before A's.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use petgraph::algo::toposort;
use petgraph::graph::{DiGraph, NodeIndex};

use crate::symbol_analysis::MergedLibrary;

/// Order the libraries being merged by their `DT_NEEDED` dependencies on each
/// other.
///
/// Returns them in constructor execution order: dependencies come before
/// dependents. For fini_array, the caller should reverse this order.
pub fn topological_order(libs: &[&MergedLibrary]) -> Result<Vec<PathBuf>> {
    let mut graph: DiGraph<&Path, ()> = DiGraph::with_capacity(libs.len(), libs.len());
    let nodes: Vec<NodeIndex> = libs
        .iter()
        .map(|lib| graph.add_node(lib.path.as_path()))
        .collect();

    // A `DT_NEEDED` entry names a soname, which is matched against the file
    // name of the library each merged soname resolved to.
    let by_file_name: HashMap<&OsStr, NodeIndex> = libs
        .iter()
        .zip(&nodes)
        .filter_map(|(lib, &node)| lib.path.file_name().map(|name| (name, node)))
        .collect();

    for (lib, &from) in libs.iter().zip(&nodes) {
        // Only a dependency that is itself being merged constrains the order;
        // the others stay dynamic, and ld.so goes on sequencing those.
        for dep in &lib.needed {
            if let Some(&to) = by_file_name.get(OsStr::new(dep.as_str())) {
                graph.add_edge(from, to, ());
            }
        }
    }

    // Edges run from dependent to dependency and `toposort` puts the tail of an
    // edge before its head, so reversing the result puts dependencies first.
    match toposort(&graph, None) {
        Ok(sorted) => Ok(sorted
            .into_iter()
            .rev()
            .map(|idx| graph[idx].to_path_buf())
            .collect()),
        Err(cycle) => bail!(
            "circular dependency detected involving library: {}",
            graph[cycle.node_id()].display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lib(soname: &str, needed: &[&str]) -> MergedLibrary {
        MergedLibrary {
            soname: soname.to_owned(),
            path: PathBuf::from("/usr/lib").join(soname),
            needed: needed.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn order(libs: &[MergedLibrary]) -> Result<Vec<String>> {
        let refs: Vec<&MergedLibrary> = libs.iter().collect();
        Ok(topological_order(&refs)?
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect())
    }

    #[test]
    fn nothing_to_merge_orders_nothing() {
        assert!(order(&[]).unwrap().is_empty());
    }

    /// The reason the ordering exists: ld.so runs a dependency's constructors
    /// before its dependent's, so the merged preinit array has to list them in
    /// that order no matter which order the executable's `DT_NEEDED` named them.
    #[test]
    fn a_dependency_runs_its_constructors_before_its_dependent() {
        let libs = [
            lib("libssl.so.3", &["libcrypto.so.3", "libc.so.6"]),
            lib("libcrypto.so.3", &["libc.so.6"]),
        ];
        assert_eq!(order(&libs).unwrap(), ["libcrypto.so.3", "libssl.so.3"]);
    }

    /// A chain only the transitive closure gets right: `libb` sits between the
    /// two, so ordering by direct dependencies alone could still put `libc`
    /// after `liba`.
    #[test]
    fn a_dependency_chain_is_ordered_end_to_end() {
        let libs = [
            lib("liba.so.1", &["libb.so.1"]),
            lib("libb.so.1", &["libc.so.1"]),
            lib("libc.so.1", &[]),
        ];
        assert_eq!(
            order(&libs).unwrap(),
            ["libc.so.1", "libb.so.1", "liba.so.1"]
        );
    }

    /// A dependency that is not being merged is still loaded by ld.so, which
    /// keeps running its constructors itself — it must not pull a library that
    /// merely shares its name into the ordering, or drop out of the result.
    #[test]
    fn a_dependency_that_stays_dynamic_does_not_constrain_the_order() {
        let libs = [
            lib("liba.so.1", &["libc.so.6", "libm.so.6"]),
            lib("libb.so.1", &["libc.so.6"]),
        ];
        let ordered = order(&libs).unwrap();
        assert_eq!(ordered.len(), 2, "{ordered:?}");
        assert!(ordered.contains(&"liba.so.1".to_owned()), "{ordered:?}");
        assert!(ordered.contains(&"libb.so.1".to_owned()), "{ordered:?}");
    }

    /// Two libraries that need each other have no constructor order that
    /// satisfies both, so the merge has to stop rather than pick one.
    #[test]
    fn a_dependency_cycle_is_reported_instead_of_ordered_arbitrarily() {
        let libs = [
            lib("liba.so.1", &["libb.so.1"]),
            lib("libb.so.1", &["liba.so.1"]),
        ];
        let err = order(&libs).expect_err("a cycle has no valid constructor order");
        assert!(
            format!("{err:#}").contains("circular dependency"),
            "{err:#}"
        );
    }
}
