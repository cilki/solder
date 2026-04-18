//! Dependency graph utilities for ordering merged libraries.
//!
//! Libraries with constructors must have their init functions called in dependency order:
//! if library A depends on library B, B's constructors must run before A's.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use petgraph::algo::toposort;
use petgraph::graph::DiGraph;

/// Topologically sort libraries by their DT_NEEDED dependencies.
///
/// Returns libraries in constructor execution order: dependencies come before dependents.
/// For fini_array, the caller should reverse this order.
pub fn topological_order(merged_libs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if merged_libs.is_empty() {
        return Ok(Vec::new());
    }

    // Build a set of merged library sonames for filtering dependencies
    let merged_sonames: HashMap<String, PathBuf> = merged_libs
        .iter()
        .filter_map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|name| (name.to_string(), p.clone()))
        })
        .collect();

    // Build a graph: node = library path, edge = dependency relationship
    let mut graph: DiGraph<PathBuf, ()> = DiGraph::new();
    let mut node_indices: HashMap<PathBuf, petgraph::graph::NodeIndex> = HashMap::new();

    // Add all libraries as nodes
    for lib in merged_libs {
        let idx = graph.add_node(lib.clone());
        node_indices.insert(lib.clone(), idx);
    }

    // Parse each library's DT_NEEDED and add edges
    for lib in merged_libs {
        let deps = parse_dt_needed(lib)?;
        let from_idx = node_indices[lib];

        for dep_soname in deps {
            // Only add edges for dependencies that are also being merged
            if let Some(dep_path) = merged_sonames.get(&dep_soname) {
                let to_idx = node_indices[dep_path];
                // Edge from dependent to dependency (A depends on B means A -> B)
                // toposort returns nodes in reverse topological order by default,
                // so we want edges pointing from dependent to dependency
                graph.add_edge(from_idx, to_idx, ());
            }
        }
    }

    // Topological sort
    match toposort(&graph, None) {
        Ok(sorted) => {
            // toposort returns nodes such that for every edge u -> v, u comes before v
            // Since our edges point from dependent to dependency, we need to reverse
            // to get dependencies first
            let result: Vec<PathBuf> = sorted
                .into_iter()
                .rev()
                .map(|idx| graph[idx].clone())
                .collect();
            Ok(result)
        }
        Err(cycle) => {
            let cycle_lib = &graph[cycle.node_id()];
            bail!(
                "circular dependency detected involving library: {}",
                cycle_lib.display()
            );
        }
    }
}

/// Parse DT_NEEDED entries from a shared library.
fn parse_dt_needed(lib_path: &Path) -> Result<Vec<String>> {
    let lib_bytes =
        std::fs::read(lib_path).with_context(|| format!("reading {}", lib_path.display()))?;

    let elf = goblin::elf::Elf::parse(&lib_bytes)
        .with_context(|| format!("parsing {}", lib_path.display()))?;

    Ok(elf.libraries.iter().map(|s| s.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_list() {
        let result = topological_order(&[]).unwrap();
        assert!(result.is_empty());
    }
}
