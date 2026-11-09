# Reusing process topology

`ProcessTreeEngine::snapshot()` and `poll()` now reuse a topology cache
internally. Existing clients benefit without changing their API calls. Reuse an
engine across polls; the one-shot `collect_snapshot()` convenience function
cannot retain a cache.

Clients that also maintain a presentation tree can use
`ProcessTreeEngine::snapshot_with_topology()`. It returns a fresh snapshot plus
an `Option<Arc<ProcessTopology>>`. With tree aggregates enabled (the default),
metric-only samples share the same topology Arc and version. Parent edges
contain both PID and creation time. The nodes are ordered by PID.

A client can retain its parent/child index while the version is unchanged and
update metrics from the fresh snapshot. On a version mismatch, replace the
structural index with `topology.parents`. This is a complete replacement, not a
delta dependent on having received every preceding sample, so reconnects and
missed updates are safe. Bridges can send only the version when the client
already knows it. Sorting, filtering, expansion, and frozen views remain client
presentation concerns.

Versions are unique within a loaded library instance, including across engine
recreation. They must not be persisted or reused after a backend restart.
`include_tree_aggregates: false` disables both aggregation and the attached
topology; existing snapshot behavior is preserved.

The cache invalidates on identity or raw parent-PID changes, arrivals and exits.
Enumeration-order and metric changes do not invalidate it. Each sample still
requires O(n) identity validation and metric aggregation; the cache removes
repeated graph construction and ordering, not process collection itself.

Missing parents attach to PID 1 when present, otherwise to the synthetic root.
Self-parenting never creates a self-edge. Cycles are broken at their lowest PID.
Traversal and aggregation are iterative, including for deep trees.

Other collectors can own a `ProcessTreeCache` and call `update()` on each fresh
raw sample. It stamps normalized parent PIDs, child PIDs, subtree metrics and
descendant counts into the records and returns the shared topology. Input must
contain unique PIDs, as a system process enumeration does. Keep raw parent PIDs
in subsequent inputs rather than recycling already-normalized output.
