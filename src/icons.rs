//! Process icon cache management.
//!
//! Icons are resolved in a background worker thread so they never block the
//! poll loop, and stamped onto `ProcessRecord`s as a `file://` URI once ready.
//!
//! On macOS, extraction uses ImageIO / CoreGraphics directly instead of
//! `NSWorkspace.iconForFile:`. NSWorkspace keeps an unbounded, process-lifetime
//! icon cache that filled resident memory with full-resolution representations
//! for every queried path; ImageIO has no such persistent cache, so resident
//! size stays flat regardless of how many icons are resolved. Linux maps
//! executables through freedesktop desktop entries and icon themes. Windows
//! asks the shell for the executable's icon and caches it as a PNG.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::model::ProcessRecord;

/// Versioned segment appended to the host-provided cache directory so that a
/// format change never reads stale files written by an older build.
const CACHE_VERSION: &str = "v1";

/// Host configuration for the icon cache. `cache_dir` is provided by the host
/// (a host-managed temp/scratch location); processtree appends a versioned
/// subdirectory.
#[derive(Debug, Clone)]
pub struct IconCacheConfig {
    pub cache_dir: PathBuf,
    pub target_px: u32,
    pub throttle: Duration,
}

impl Default for IconCacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: std::env::temp_dir().join("processtree/icons"),
            target_px: 128,
            throttle: Duration::from_millis(4),
        }
    }
}

/// Result of resolving a single icon source.
enum Resolution {
    /// Source produced application metadata, optionally including an icon.
    Ready(ResolvedSource),
    /// Source has been inspected and either has no resolvable icon or the
    /// extraction failed. Recorded so the worker does not retry it forever.
    NoIcon,
}

#[derive(Clone)]
struct ResolvedSource {
    icon_uri: Option<String>,
    application_name: Option<String>,
}

/// Shared worker state behind the icon mutex.
struct WorkerState {
    queue: Vec<String>,
    queued: HashSet<String>,
    ready: HashMap<String, ResolvedSource>,
    no_icon: HashSet<String>,
    shutdown: bool,
}

impl WorkerState {
    fn is_unknown(&self, source: &str) -> bool {
        !self.ready.contains_key(source)
            && !self.no_icon.contains(source)
            && !self.queued.contains(source)
    }
}

/// Background icon cache. Cheap to query from the poll thread; all extraction
/// happens on the worker thread.
pub struct IconCache {
    shared: Arc<IconShared>,
    handle: Mutex<Option<JoinHandle<()>>>,
    alive: Arc<AtomicBool>,
}

struct IconShared {
    state: Mutex<WorkerState>,
    cvar: Condvar,
}

impl IconCache {
    pub fn new(config: IconCacheConfig) -> Self {
        let shared = Arc::new(IconShared {
            state: Mutex::new(WorkerState {
                queue: Vec::new(),
                queued: HashSet::new(),
                ready: HashMap::new(),
                no_icon: HashSet::new(),
                shutdown: false,
            }),
            cvar: Condvar::new(),
        });
        let alive = Arc::new(AtomicBool::new(true));
        let worker_shared = Arc::clone(&shared);
        let worker_alive = Arc::clone(&alive);
        let handle = thread::Builder::new()
            .name("processtree-icon-worker".to_string())
            .spawn(move || worker_loop(worker_shared, config, worker_alive))
            .expect("spawn icon worker");
        Self {
            shared,
            handle: Mutex::new(Some(handle)),
            alive,
        }
    }

    /// Enqueue any freshly-seen sources and stamp ready icons onto records,
    /// all under a single lock. Records without a ready icon keep `icon_uri =
    /// None`, which the host renders as a fallback.
    pub fn stamp(&self, records: &mut [ProcessRecord]) {
        let mut state = self.shared.state.lock().expect("icon state lock");
        let mut wake = false;
        for record in records.iter_mut() {
            let source = icon_source_key(record);
            if source.is_empty() {
                continue;
            }
            if let Some(resolved) = state.ready.get(&source) {
                record.icon_uri.clone_from(&resolved.icon_uri);
                if let Some(application_name) = &resolved.application_name {
                    record.name =
                        crate::platform::application_display_name(record, application_name);
                }
                continue;
            }
            if state.is_unknown(&source) {
                state.queued.insert(source.clone());
                state.queue.push(source);
                wake = true;
            }
        }
        drop(state);
        if wake {
            self.shared.cvar.notify_one();
        }
    }

    /// Snapshot of ready URIs, mainly for introspection and tests.
    pub fn ready_uris(&self) -> HashMap<String, String> {
        self.shared
            .state
            .lock()
            .expect("icon state lock")
            .ready
            .iter()
            .filter_map(|(source, resolved)| {
                resolved
                    .icon_uri
                    .as_ref()
                    .map(|uri| (source.clone(), uri.clone()))
            })
            .collect()
    }

    pub fn shutdown(&self) {
        {
            let mut state = self.shared.state.lock().expect("icon state lock");
            state.shutdown = true;
        }
        self.alive.store(false, Ordering::Release);
        self.shared.cvar.notify_all();
        if let Ok(mut handle_slot) = self.handle.lock() {
            if let Some(handle) = handle_slot.take() {
                let _ = handle.join();
            }
        }
    }
}

fn icon_source_key(record: &ProcessRecord) -> String {
    #[cfg(target_os = "linux")]
    if record.status == crate::model::ProcessStatus::Zombie {
        // A zombie retains its systemd cgroup after Linux removes its
        // executable and command line. Resolving that inherited application
        // ID would replace the kernel process name with the containing desktop
        // application's name and icon.
        return String::new();
    }
    #[cfg(target_os = "linux")]
    if !record.application_id.is_empty() {
        return format!("{}\0{}", record.application_id, record.app_bundle_path);
    }
    record.app_bundle_path.clone()
}

impl Drop for IconCache {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn worker_loop(shared: Arc<IconShared>, config: IconCacheConfig, alive: Arc<AtomicBool>) {
    let _ = std::fs::create_dir_all(versioned_cache_dir(&config.cache_dir));

    #[cfg(target_os = "linux")]
    let mut resolver = linux::IconResolver::from_environment();
    #[cfg(target_os = "linux")]
    let mut last_refresh = std::time::Instant::now();

    while alive.load(Ordering::Acquire) {
        #[cfg(target_os = "linux")]
        if last_refresh.elapsed() >= LINUX_CATALOG_REFRESH_INTERVAL {
            refresh_linux_catalog(&shared, &mut resolver);
            last_refresh = std::time::Instant::now();
        }
        let source = next_source(&shared);
        let Some(source) = source else {
            continue;
        };

        let resolution = resolve_source(
            &source,
            &config,
            #[cfg(target_os = "linux")]
            &resolver,
        );
        {
            let mut state = shared.state.lock().expect("icon state lock");
            match resolution {
                Resolution::Ready(resolved) => {
                    state.ready.insert(source.clone(), resolved);
                }
                Resolution::NoIcon => {
                    state.no_icon.insert(source);
                }
            }
        }

        if config.throttle > Duration::ZERO {
            thread::sleep(config.throttle);
        }
    }
}

/// Pull the next source to process, waiting on the condvar when idle.
/// Returns `None` on shutdown or a Linux catalog refresh timeout.
fn next_source(shared: &IconShared) -> Option<String> {
    let mut state = shared.state.lock().expect("icon state lock");
    loop {
        if state.shutdown {
            return None;
        }
        if let Some(source) = state.queue.pop() {
            state.queued.remove(&source);
            return Some(source);
        }
        #[cfg(target_os = "linux")]
        {
            let (next, timeout) = shared
                .cvar
                .wait_timeout(state, LINUX_CATALOG_REFRESH_INTERVAL)
                .expect("icon cvar");
            state = next;
            if timeout.timed_out() {
                return None;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            state = shared.cvar.wait(state).expect("icon cvar");
        }
    }
}

#[cfg(target_os = "linux")]
const LINUX_CATALOG_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
fn refresh_linux_catalog(shared: &IconShared, resolver: &mut linux::IconResolver) {
    if resolver.refresh() {
        let mut state = shared.state.lock().expect("icon state lock");
        state.ready.clear();
        state.no_icon.clear();
        // Active sources are requeued by the next stamp, so exited processes
        // do not accumulate work after an installation or removal.
    }
}

fn resolve_source(
    source: &str,
    config: &IconCacheConfig,
    #[cfg(target_os = "linux")] resolver: &linux::IconResolver,
) -> Resolution {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let cache_dir = versioned_cache_dir(&config.cache_dir);

    #[cfg(target_os = "macos")]
    {
        match macos::produce_icon(source, &cache_dir, config.target_px) {
            Ok(uri) => Resolution::Ready(ResolvedSource {
                icon_uri: Some(uri),
                application_name: None,
            }),
            Err(macos::ExtractError::NoIcon | macos::ExtractError::Failed(_)) => Resolution::NoIcon,
        }
    }

    #[cfg(target_os = "linux")]
    {
        let (application_id, executable) = source
            .split_once('\0')
            .map_or(("", source), |(application_id, executable)| {
                (application_id, executable)
            });
        match resolver.resolve_application(executable, application_id, config.target_px) {
            Some(application) => Resolution::Ready(ResolvedSource {
                icon_uri: application.icon_uri,
                application_name: Some(application.name),
            }),
            None => Resolution::NoIcon,
        }
    }

    #[cfg(target_os = "windows")]
    {
        match windows::produce_icon(source, &cache_dir, config.target_px) {
            Ok(uri) => Resolution::Ready(ResolvedSource {
                icon_uri: Some(uri),
                application_name: None,
            }),
            Err(windows::ExtractError::NoIcon | windows::ExtractError::Failed) => {
                Resolution::NoIcon
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (source, &config.cache_dir, config.target_px);
        Resolution::NoIcon
    }
}

fn versioned_cache_dir(cache_dir: &Path) -> PathBuf {
    cache_dir.join(CACHE_VERSION)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn catalog_change_invalidates_successes_and_failed_lookups() {
        let root =
            std::env::temp_dir().join(format!("processtree-invalidate-{}", std::process::id()));
        let applications = root.join("applications");
        std::fs::create_dir_all(&applications).unwrap();
        let mut resolver = linux::IconResolver::from_data_dirs(vec![root.clone()], vec![]);
        let shared = IconShared {
            state: Mutex::new(WorkerState {
                queue: vec![],
                queued: HashSet::new(),
                ready: HashMap::from([(
                    "existing".into(),
                    ResolvedSource {
                        icon_uri: None,
                        application_name: Some("Old Name".into()),
                    },
                )]),
                no_icon: HashSet::from(["/opt/maillama/maillama".into()]),
                shutdown: false,
            }),
            cvar: Condvar::new(),
        };
        refresh_linux_catalog(&shared, &mut resolver);
        assert!(!shared
            .state
            .lock()
            .unwrap()
            .is_unknown("/opt/maillama/maillama"));
        std::fs::write(
            applications.join("de.devmil.maillama.desktop"),
            "[Desktop Entry]\nName=MailLama\nExec=maillama\n",
        )
        .unwrap();
        refresh_linux_catalog(&shared, &mut resolver);
        let state = shared.state.lock().unwrap();
        assert!(state.is_unknown("/opt/maillama/maillama"));
        assert!(state.is_unknown("existing"));
        drop(state);
        assert!(
            matches!(resolve_source("de.devmil.maillama\0/opt/maillama/maillama", &IconCacheConfig::default(), &resolver), Resolution::Ready(ResolvedSource { application_name: Some(name), .. }) if name == "MailLama")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn zombie_does_not_inherit_desktop_application_metadata() {
        let mut record = ProcessRecord::synthetic(42, 7, "git");
        record.status = crate::model::ProcessStatus::Zombie;
        record.app_bundle_path = "/usr/bin/git".to_string();
        record.application_id = "code".to_string();

        assert!(icon_source_key(&record).is_empty());
        assert_eq!(record.name, "git");
        assert!(record.icon_uri.is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn produces_png_for_a_system_app() {
        let cache_dir =
            std::env::temp_dir().join(format!("processtree-icon-prod-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache_dir);

        // Finder ships on every macOS install and always carries an icon.
        let source = "/System/Library/CoreServices/Finder.app";
        let uri = macos::produce_icon(source, &versioned_cache_dir(&cache_dir), 128)
            .expect("finder icon uri");

        assert!(uri.starts_with("file://"));
        let path = uri_to_path(&uri);
        let bytes = std::fs::read(&path).expect("cached png bytes");
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));

        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn second_call_hits_disk_cache_without_changing_path() {
        let cache_dir = std::env::temp_dir().join(format!(
            "processtree-icon-cached-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&cache_dir);
        let dir = versioned_cache_dir(&cache_dir);

        let first = macos::produce_icon("/System/Library/CoreServices/Finder.app", &dir, 128)
            .expect("first uri");
        let second = macos::produce_icon("/System/Library/CoreServices/Finder.app", &dir, 128)
            .expect("second uri");
        assert_eq!(first, second);

        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stamp_enqueues_unseen_sources_and_applies_ready_uris() {
        let cache = IconCache::new(IconCacheConfig {
            cache_dir: std::env::temp_dir().join(format!(
                "processtree-icon-stamp-test-{}",
                std::process::id()
            )),
            throttle: Duration::ZERO,
            ..IconCacheConfig::default()
        });

        let mut record = ProcessRecord::synthetic(1, 0, "Finder");
        record.app_bundle_path = "/System/Library/CoreServices/Finder.app".to_string();
        cache.stamp(std::slice::from_mut(&mut record));

        // The worker will eventually populate the ready map; the stamp itself
        // only guarantees the source was enqueued and left icon_uri unset until
        // a ready result exists.
        let mut observed = false;
        for _ in 0..200 {
            if let Some(uri) = cache.ready_uris().get(record.app_bundle_path.as_str()) {
                assert!(uri.starts_with("file://"));
                observed = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(observed, "icon worker never produced a ready uri");

        let mut next = ProcessRecord::synthetic(1, 0, "Finder");
        next.app_bundle_path = record.app_bundle_path.clone();
        cache.stamp(std::slice::from_mut(&mut next));
        assert!(next.icon_uri.as_deref().unwrap().starts_with("file://"));

        cache.shutdown();
    }

    #[cfg(target_os = "macos")]
    fn uri_to_path(uri: &str) -> PathBuf {
        let stripped = uri.strip_prefix("file://").unwrap_or(uri);
        let mut out = String::new();
        let mut chars = stripped.chars();
        while let Some(c) = chars.next() {
            if c == '%' {
                let hi = chars.next().unwrap_or('0');
                let lo = chars.next().unwrap_or('0');
                let byte = u8::from_str_radix(&format!("{hi}{lo}"), 16).unwrap_or(0);
                out.push(byte as char);
            } else {
                out.push(c);
            }
        }
        PathBuf::from(out)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::CStr;
    use std::path::PathBuf;

    use super::{file_uri, hash_source, source_mtime};
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;

    type CfRef = *const core::ffi::c_void;

    const K_CF_ALLOCATOR_DEFAULT: CfRef = core::ptr::null();
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_CF_PROPERTY_LIST_IMMUTABLE: u32 = 0;
    const K_CF_URL_POSIX_PATH_STYLE: isize = 0;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDataCreate(allocator: CfRef, bytes: *const u8, length: isize) -> CfRef;
        fn CFRelease(cf: CfRef);
        fn CFPropertyListCreateWithData(
            allocator: CfRef,
            data: CfRef,
            options: u32,
            format: *mut u32,
            error: *mut CfRef,
        ) -> CfRef;
        fn CFGetTypeID(cf: CfRef) -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFDictionaryGetTypeID() -> usize;
        fn CFDictionaryGetValue(dict: CfRef, key: CfRef) -> CfRef;
        fn CFStringGetCStringPtr(s: CfRef, encoding: u32) -> *const core::ffi::c_char;
        fn CFStringGetCString(
            s: CfRef,
            buffer: *mut core::ffi::c_char,
            buffer_size: isize,
            encoding: u32,
        ) -> u8;
        fn CFURLCreateWithFileSystemPath(
            allocator: CfRef,
            file_path: CfRef,
            path_style: isize,
            is_directory: u8,
        ) -> CfRef;
    }

    #[link(name = "ImageIO", kind = "framework")]
    unsafe extern "C" {
        fn CGImageSourceCreateWithURL(url: CfRef, options: CfRef) -> CfRef;
        fn CGImageSourceGetCount(source: CfRef) -> isize;
        fn CGImageSourceCreateImageAtIndex(source: CfRef, index: isize, options: CfRef) -> CfRef;
        fn CGImageDestinationCreateWithURL(
            url: CfRef,
            type_id: CfRef,
            count: isize,
            options: CfRef,
        ) -> CfRef;
        fn CGImageDestinationAddImage(dest: CfRef, image: CfRef, properties: CfRef);
        fn CGImageDestinationFinalize(dest: CfRef) -> u8;
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGImageGetWidth(image: CfRef) -> isize;
        fn CGImageGetHeight(image: CfRef) -> isize;
        fn CGImageRelease(image: CfRef);
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    pub enum ExtractError {
        /// Source is not a usable app bundle (no Info.plist / no icon entry).
        NoIcon,
        /// Extraction was attempted but failed at the ImageIO layer.
        Failed(String),
    }

    /// Resolve `bundle_path` to a `file://` URI for its cached PNG, generating
    /// and writing the PNG on the first call. The disk cache is keyed by the
    /// source path hash plus the bundle mtime, so an app update invalidates it.
    pub fn produce_icon(
        bundle_path: &str,
        cache_dir: &std::path::Path,
        target_px: u32,
    ) -> Result<String, ExtractError> {
        let mtime = source_mtime(bundle_path);
        let cache_file = cache_dir.join(format!(
            "{:016x}-{:016x}.png",
            hash_source(bundle_path),
            mtime
        ));
        if cache_file.exists() {
            return Ok(file_uri(&cache_file));
        }

        let icns_path = resolve_bundle_icns(bundle_path)?;
        let png_path = render_icns_to_png(&icns_path, &cache_file, target_px as isize)?;
        Ok(file_uri(&png_path))
    }

    fn resolve_bundle_icns(bundle_path: &str) -> Result<PathBuf, ExtractError> {
        let info_plist = std::path::Path::new(bundle_path).join("Contents/Info.plist");
        let bytes = std::fs::read(&info_plist).map_err(|_| ExtractError::NoIcon)?;
        let icon_name = read_bundle_icon_file(&bytes).ok_or(ExtractError::NoIcon)?;

        let file_name = if icon_name.ends_with(".icns") {
            icon_name
        } else {
            format!("{icon_name}.icns")
        };
        let icns = std::path::Path::new(bundle_path)
            .join("Contents/Resources")
            .join(file_name);
        if !icns.exists() {
            return Err(ExtractError::NoIcon);
        }
        Ok(icns)
    }

    fn read_bundle_icon_file(info_plist_bytes: &[u8]) -> Option<String> {
        unsafe {
            let data = CFDataCreate(
                K_CF_ALLOCATOR_DEFAULT,
                info_plist_bytes.as_ptr(),
                info_plist_bytes.len() as isize,
            );
            if data.is_null() {
                return None;
            }

            let plist = CFPropertyListCreateWithData(
                K_CF_ALLOCATOR_DEFAULT,
                data,
                K_CF_PROPERTY_LIST_IMMUTABLE,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            CFRelease(data);
            if plist.is_null() {
                return None;
            }

            let result = (|| {
                if CFGetTypeID(plist) != CFDictionaryGetTypeID() {
                    return None;
                }
                let key = CFString::new("CFBundleIconFile");
                let value = CFDictionaryGetValue(plist, key.as_concrete_TypeRef() as CfRef);
                if value.is_null() || CFGetTypeID(value) != CFStringGetTypeID() {
                    return None;
                }
                cfstring_ptr_to_string(value)
            })();

            CFRelease(plist);
            result
        }
    }

    unsafe fn cfstring_ptr_to_string(value: CfRef) -> Option<String> {
        let ptr = CFStringGetCStringPtr(value, K_CF_STRING_ENCODING_UTF8);
        if !ptr.is_null() {
            return Some(CStr::from_ptr(ptr).to_string_lossy().into_owned());
        }

        // Fall back to a copied buffer when the internal representation is not
        // backed by a C string (e.g. a UTF-16 inline buffer).
        let mut buffer = vec![0i8; 1024];
        let ok = CFStringGetCString(
            value,
            buffer.as_mut_ptr(),
            buffer.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
        );
        if ok == 0 {
            return None;
        }
        let cstr = CStr::from_ptr(buffer.as_ptr());
        Some(cstr.to_string_lossy().into_owned())
    }

    fn render_icns_to_png(
        icns_path: &std::path::Path,
        out_path: &std::path::Path,
        target_px: isize,
    ) -> Result<PathBuf, ExtractError> {
        if let Some(parent) = out_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        unsafe {
            let icns_url = make_file_url(icns_path)?;
            let source = CGImageSourceCreateWithURL(icns_url, core::ptr::null());
            CFRelease(icns_url);
            if source.is_null() {
                return Err(ExtractError::Failed("image source null".to_string()));
            }

            let index = select_best_representation(source, target_px);
            if index < 0 {
                cf_release(source);
                return Err(ExtractError::Failed("no bitmap representation".to_string()));
            }

            let image = CGImageSourceCreateImageAtIndex(source, index, core::ptr::null());
            cf_release(source);
            if image.is_null() {
                return Err(ExtractError::Failed("image null".to_string()));
            }

            let out_url = make_file_url(out_path)?;
            let png_type = CFString::new("public.png");
            let dest = CGImageDestinationCreateWithURL(
                out_url,
                png_type.as_concrete_TypeRef() as CfRef,
                1,
                core::ptr::null(),
            );
            CFRelease(out_url);
            if dest.is_null() {
                CGImageRelease(image);
                return Err(ExtractError::Failed("destination null".to_string()));
            }

            CGImageDestinationAddImage(dest, image, core::ptr::null());
            CGImageRelease(image);
            let finalized = CGImageDestinationFinalize(dest);
            CFRelease(dest);

            if finalized == 0 || !out_path.exists() {
                return Err(ExtractError::Failed("finalize failed".to_string()));
            }
        }

        Ok(out_path.to_path_buf())
    }

    unsafe fn select_best_representation(source: CfRef, target_px: isize) -> isize {
        let count = CGImageSourceGetCount(source);
        let mut best: isize = -1;
        let mut best_score = isize::MAX;

        for index in 0..count {
            let image = CGImageSourceCreateImageAtIndex(source, index, core::ptr::null());
            if image.is_null() {
                continue;
            }
            let wide = CGImageGetWidth(image);
            let high = CGImageGetHeight(image);
            CGImageRelease(image);
            if wide <= 0 || high <= 0 {
                continue;
            }
            let edge = wide.max(high);
            let score = (edge - target_px).abs();
            if best < 0 || score < best_score {
                best = index;
                best_score = score;
            }
        }

        best
    }

    unsafe fn make_file_url(path: &std::path::Path) -> Result<CfRef, ExtractError> {
        let path_string = CFString::new(path.to_string_lossy().as_ref());
        let url = CFURLCreateWithFileSystemPath(
            K_CF_ALLOCATOR_DEFAULT,
            path_string.as_concrete_TypeRef() as CfRef,
            K_CF_URL_POSIX_PATH_STYLE,
            0,
        );
        if url.is_null() {
            return Err(ExtractError::Failed(format!(
                "url null for {}",
                path.display()
            )));
        }
        Ok(url)
    }

    unsafe fn cf_release(cf: CfRef) {
        CFRelease(cf);
    }
}

/// Deterministic hash of a source path for cache file naming. `DefaultHasher`
/// uses fixed seeds, so results are stable across runs of the same toolchain;
/// the cache is disposable, so cross-toolchain drift only forces regeneration.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn hash_source(source: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    source.hash(&mut hasher);
    hasher.finish()
}

/// Bundle directory mtime in seconds since UNIX epoch. Used as an invalidation
/// signal so an app update produces a fresh icon. Falls back to 0 on error.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn source_mtime(path: &str) -> u64 {
    std::fs::metadata(Path::new(path))
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// Build a percent-encoded `file://` URI for a path. Cache filenames are hex,
/// but the host-provided cache directory may contain spaces or non-ASCII.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn file_uri(path: &Path) -> String {
    let mut out = String::from("file://");
    for byte in path.to_string_lossy().as_bytes() {
        match byte {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;
