# processtree

A Rust library for process telemetry, process trees and inspection on Linux, macOS
and Windows. ProcessLama uses it through a separate telemetry and Flutter bridge layer.

Keep a ProcessTreeEngine across polls to reuse topology and icon caches. Processes
are identified by PID and creation time so PID reuse does not merge unrelated samples.
See docs/topology-cache.md for stable topology versions and src/lib.rs for the public API.

```sh
cargo test --locked
cargo check --all-targets --locked
```

Some metrics depend on OS permissions and optional platform facilities. Linux network
rates can use a configured external network snapshot file. EngineConfig exposes the
path; callers should configure it for their service rather than rely on the historical
default. The library does not install a privileged service.

Licensed under MIT. See LICENSE.
