//! Windows SCM boundary for a dedicated helper executable. The SCM entry point
//! has no context parameter, so one explicit invocation is transferred through
//! a process-local slot. Workers and callback state remain owned by service_main.
use crate::network::windows::WindowsNetworkCollector;
use std::io;
use std::path::PathBuf;
use std::ptr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::Duration;
use windows_sys::core::w;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::{Services::*, Threading::*};

struct Config {
    name: Vec<u16>,
    trace: String,
    endpoint: PathBuf,
}
static CONFIG: OnceLock<Config> = OnceLock::new();
static CONTROL: OnceLock<Control> = OnceLock::new();

pub fn run(name: &str, trace: &str, endpoint: PathBuf) -> io::Result<()> {
    if super::handle_files_subcommand() {
        return Ok(());
    }
    CONFIG
        .set(Config {
            name: name.encode_utf16().chain(Some(0)).collect(),
            trace: trace.into(),
            endpoint,
        })
        .map_err(|_| io::Error::other("service already configured"))?;
    let config = CONFIG.get().unwrap();
    let entries = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: config.name.as_ptr() as *mut _,
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
struct Control {
    stop: AtomicBool,
}
unsafe extern "system" fn control(
    code: u32,
    _: u32,
    _: *mut core::ffi::c_void,
    context: *mut core::ffi::c_void,
) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        unsafe { &*context.cast::<Control>() }
            .stop
            .store(true, Ordering::Release);
    }
    ERROR_SUCCESS
}
unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let config = CONFIG.get().unwrap();
    let control_state = CONTROL.get_or_init(|| Control {
        stop: AtomicBool::new(false),
    });
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            config.name.as_ptr(),
            Some(control),
            (control_state as *const Control).cast_mut().cast(),
        )
    };
    if handle.is_null() {
        return;
    }
    report(handle, SERVICE_START_PENDING, 0);
    enable_debug_privilege();
    let result = collect(config, control_state, handle);
    report(
        handle,
        SERVICE_STOPPED,
        if result.is_ok() {
            0
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
    );
}
fn report(handle: SERVICE_STATUS_HANDLE, state: u32, error: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: error,
        dwServiceSpecificExitCode: u32::from(error != 0),
        dwCheckPoint: u32::from(state == SERVICE_START_PENDING),
        dwWaitHint: if state == SERVICE_START_PENDING {
            5000
        } else {
            0
        },
    };
    unsafe {
        SetServiceStatus(handle, &status);
    }
}
fn collect(config: &Config, control: &Control, handle: SERVICE_STATUS_HANDLE) -> io::Result<()> {
    let latest = Arc::new(Mutex::new(None));
    let published = Arc::clone(&latest);
    // Claim the fixed endpoint before reclaiming our orphan ETW session. A
    // second helper must not interrupt the collector owned by a running helper.
    let _server = super::HelperServer::start(config.endpoint.clone(), move || {
        published.lock().ok().and_then(|value| value.clone())
    })?;
    let collector = WindowsNetworkCollector::start(&config.trace)?;
    report(handle, SERVICE_RUNNING, 0);
    while !control.stop.load(Ordering::Acquire) {
        let sample = collector.snapshot()?;
        *latest
            .lock()
            .map_err(|_| io::Error::other("helper state unavailable"))? = Some(sample);
        for _ in 0..25 {
            if control.stop.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    report(handle, SERVICE_STOP_PENDING, 0);
    Ok(())
}
fn enable_debug_privilege() {
    let mut token = ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    } == 0
    {
        return;
    }
    let mut luid = LUID::default();
    if unsafe { LookupPrivilegeValueW(ptr::null(), w!("SeDebugPrivilege"), &mut luid) } != 0 {
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        unsafe {
            AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut());
        }
    }
    unsafe {
        CloseHandle(token);
    }
}
