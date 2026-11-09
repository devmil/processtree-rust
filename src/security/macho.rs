//! Mach-O architecture detection for security overview.

use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

const FAT_MAGIC: u32 = 0xcafe_babe;
const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_ARCH_ABI64: i32 = 0x0100_0000;
const CPU_TYPE_ARM: i32 = 12;
const CPU_TYPE_I386: i32 = 7;
const CPU_TYPE_ARM64: i32 = 0x0100_000c;
const CPU_TYPE_X86_64: i32 = 0x0100_0007;

pub fn architectures_for_path(path: &str) -> Vec<&'static str> {
    if path.is_empty() {
        return Vec::new();
    }
    let Ok(mut file) = File::open(Path::new(path)) else {
        return Vec::new();
    };
    let mut header = [0u8; 8];
    if file.read_exact(&mut header).is_err() {
        return Vec::new();
    }
    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if magic == FAT_MAGIC {
        return fat_architectures(&mut file);
    }
    if magic == MH_MAGIC_64 || magic == MH_MAGIC {
        return vec![cpu_type_name(read_cpu_type(&mut file, 0))];
    }
    Vec::new()
}

fn fat_architectures(file: &mut File) -> Vec<&'static str> {
    let mut buf = [0u8; 8];
    if file.read_exact(&mut buf).is_err() {
        return Vec::new();
    }
    let nfat = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let mut archs = Vec::new();
    for _ in 0..nfat.min(8) {
        let mut fat_arch = [0u8; 20];
        if file.read_exact(&mut fat_arch).is_err() {
            break;
        }
        let cputype = i32::from_be_bytes([fat_arch[0], fat_arch[1], fat_arch[2], fat_arch[3]]);
        let name = cpu_type_name(cputype);
        if !archs.contains(&name) {
            archs.push(name);
        }
    }
    archs
}

fn read_cpu_type(file: &mut File, base: u64) -> i32 {
    let mut buf = [0u8; 8];
    if file.seek(std::io::SeekFrom::Start(base + 4)).is_err() {
        return 0;
    }
    if file.read_exact(&mut buf).is_err() {
        return 0;
    }
    i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

fn cpu_type_name(cputype: i32) -> &'static str {
    if cputype == CPU_TYPE_ARM64 {
        return "arm64";
    }
    if cputype == CPU_TYPE_X86_64 {
        return "x86_64";
    }
    let base = cputype & 0xff;
    let is64 = (cputype & CPU_ARCH_ABI64) != 0;
    match (base, is64) {
        (CPU_TYPE_ARM, true) => "arm64",
        (CPU_TYPE_ARM, false) => "arm",
        (CPU_TYPE_I386, true) => "x86_64",
        (CPU_TYPE_I386, false) => "i386",
        _ => "unknown",
    }
}

/// Host CPU label when on-disk Mach-O cannot be classified.
pub fn architecture_host_fallback() -> String {
    #[cfg(target_arch = "aarch64")]
    return "arm64".into();
    #[cfg(target_arch = "x86_64")]
    return "x86_64".into();
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    return "unknown".into();
}

pub fn architecture_summary(path: &str) -> String {
    let archs = architectures_for_path(path);
    if archs.is_empty() {
        return architecture_host_fallback();
    }
    if archs.len() >= 2 {
        format!("universal ({})", archs.join(", "))
    } else {
        archs[0].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fat_header_magic() {
        assert_eq!(FAT_MAGIC, 0xcafe_babe);
    }

    #[test]
    fn cpu_type_name_arm64_slice() {
        assert_eq!(cpu_type_name(CPU_TYPE_ARM64), "arm64");
        assert_eq!(cpu_type_name(CPU_TYPE_X86_64), "x86_64");
        assert_eq!(cpu_type_name(CPU_TYPE_ARM | CPU_ARCH_ABI64), "arm64");
    }
}
