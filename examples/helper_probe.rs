fn main() -> std::io::Result<()> {
    if processtree::helper::handle_files_subcommand() {
        return Ok(());
    }
    processtree::helper::self_test_files()?;
    println!("PASS: helper open-file inspection and stale process identity");
    #[cfg(windows)]
    if std::env::args().any(|arg| arg == "--network") {
        processtree::network::windows::self_test()?;
        println!("PASS: TCP/UDP IPv4/IPv6 byte collection and trace restart");
    }
    #[cfg(windows)]
    if std::env::args().any(|arg| arg == "--service") {
        service_probe()?;
        println!("PASS: service file inspection and fresh network snapshots");
    }
    Ok(())
}

#[cfg(windows)]
fn service_probe() -> std::io::Result<()> {
    use std::{io, path::Path, thread, time::Duration};
    let endpoint = Path::new(r"\\.\pipe\HoddmimisTelemetry");
    let file_path =
        std::env::temp_dir().join(format!("hoddmimis-service-probe-{}", std::process::id()));
    let file = std::fs::File::create(&file_path)?;
    let identity = processtree::enumerate_processes()
        .map_err(io::Error::other)?
        .into_iter()
        .find(|p| p.pid() == std::process::id() as i32)
        .ok_or_else(|| io::Error::other("probe process missing"))?
        .identity;
    let files = processtree::helper::file_descriptors(endpoint, identity);
    let filename = file_path.file_name().unwrap().to_string_lossy();
    let found = files
        .descriptors
        .iter()
        .any(|f| f.path.ends_with(&*filename));
    drop(file);
    std::fs::remove_file(file_path)?;
    if !found {
        return Err(io::Error::other("service open-file probe failed"));
    }
    let before = processtree::helper::network_snapshot(endpoint)?;
    thread::sleep(Duration::from_secs(1));
    let after = processtree::helper::network_snapshot(endpoint)?;
    if after.captured_at_unix_ms <= before.captured_at_unix_ms
        || !after
            .processes
            .iter()
            .any(|p| p.pid == identity.pid && p.start_time_unix_ms == identity.start_time_unix_ms)
    {
        return Err(io::Error::other(
            "service snapshot freshness/identity failed",
        ));
    }
    Ok(())
}
