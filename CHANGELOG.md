# Changelog

## Unreleased

- Report listening ports separately in process samples: TCP listeners and UDP
  sockets bound to a well-known port (below 1024). `local_ports` still lists
  every local port, including outgoing connections.

- Tolerate macOS process-table growth between sysctl sizing and reading: add
  headroom, re-probe and retry ENOMEM with a bounded budget, discard partial
  reads, and preserve the OS error code for other enumeration failures.

- Report sorted local TCP/UDP ports in process samples using one socket-table
  scan per poll. Add cross-platform batch socket enumeration and Linux/Windows
  socket inspector support through native OS APIs. Unreported ownership remains
  unavailable rather than implying a process has no ports.

- Refresh Linux desktop application metadata while running, including retrying
  cached misses after applications are installed, updated or removed.

- Cache process topology across metric-only polls, including parent identities,
  child lists, descendant counts and iterative aggregation order. All engine
  snapshot and polling clients benefit automatically. PID reuse, reparenting,
  arrivals and exits invalidate the cache; enumeration order does not.
- Expose `ProcessTreeCache` and `snapshot_with_topology()` for consumers that
  want to reuse identity-safe, versioned structural state between samples.
- Normalize cyclic parent links into deterministic acyclic trees, avoiding
  double-counted metrics and recursive stack growth on deep process trees.

- Prefer an exact Flatpak cgroup identity over Bubblewrap's sandbox command,
  so wrappers for applications such as Bitwarden and Obsidian resolve reliably.
- Add an owned Windows ETW collector for per-process TCP/UDP IPv4/IPv6 bytes,
  identity-backed helper snapshots, and helper restart/staleness handling.
- Add a bounded local helper protocol for open-file metadata on Linux and
  Windows. Windows uses Process Snapshotting; file queries run in finite child
  processes and validate the process start time before and after inspection.
- Add native helper probes for file transport, PID identity, ETW traffic, and
  collector shutdown. Windows ETW collection requires a privileged helper.

- Resolve Windows executable icons through the shell and cache them as PNGs
  for process-tree clients.

- Added Windows process enumeration with creation-time identity, parent links,
  CPU and memory metrics, executable paths, account names, handle and thread
  counts, and terminate, kill, suspend, and resume actions.
- Resolve Bubblewrap rows from an exact Flatpak cgroup application ID when the
  desktop entry declares the same `X-Flatpak` identity.
- Resolve Flatpak applications whose sandbox executable uses an earlier
  desktop ID, including Bitwarden's `bitwarden-app` process.
- Resolve Bubblewrap's explicit sandbox entrypoint as application metadata, so
  wrapper rows can show the owning desktop application's name and icon without
  changing the process hierarchy.
- Resolve Linux application names and icons from systemd cgroup desktop IDs
  before falling back to executable matching.
- Added Linux `/proc` process enumeration, CPU and memory metrics, process
  actions, open-file inspection, thread inspection, and permission-aware detail
  states.
- Added Linux per-process GPU sampling for DRM drivers that publish engine
  nanoseconds through `/proc/<pid>/fdinfo`. Sampling is limited to accessible
  processes and deduplicates repeated DRM client descriptions.
- Publish cumulative Linux helper and macOS `nettop` network totals from the
  first valid sample. Rates still require two samples with an elapsed interval.
- Added a macOS `nettop` watchdog that restarts the managed sampler when it
  stops producing samples or its child `nettop` process stays at high CPU for
  several consecutive polls.
