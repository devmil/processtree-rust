use std::fs::File;
use std::io::BufWriter;
use std::mem;
use std::path::Path;

use windows_sys::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO, BITMAPINFOHEADER,
    BI_RGB, DIB_RGB_COLORS,
};
use windows_sys::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};
use windows_sys::Win32::UI::Shell::{
    SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON, SHGFI_SMALLICON,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

use super::{hash_source, source_mtime};

#[derive(Debug)]
pub enum ExtractError {
    NoIcon,
    Failed,
}

struct OwnedIcon(windows_sys::Win32::UI::WindowsAndMessaging::HICON);

impl Drop for OwnedIcon {
    fn drop(&mut self) {
        unsafe {
            DestroyIcon(self.0);
        }
    }
}

struct OwnedBitmap(windows_sys::Win32::Graphics::Gdi::HBITMAP);

impl Drop for OwnedBitmap {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                DeleteObject(self.0);
            }
        }
    }
}

struct ComApartment;

impl ComApartment {
    fn initialize() -> Result<Self, ExtractError> {
        let apartment_threaded =
            u32::try_from(COINIT_APARTMENTTHREADED).expect("COM initialization flag");
        let result = unsafe { CoInitializeEx(std::ptr::null(), apartment_threaded) };
        (result >= 0).then_some(Self).ok_or(ExtractError::Failed)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

pub fn produce_icon(
    executable_path: &str,
    cache_dir: &Path,
    target_px: u32,
) -> Result<String, ExtractError> {
    if executable_path.is_empty() || !Path::new(executable_path).is_file() {
        return Err(ExtractError::NoIcon);
    }

    let cache_file = cache_dir.join(format!(
        "{:016x}-{:016x}.png",
        hash_source(executable_path),
        source_mtime(executable_path)
    ));
    if cache_file.exists() {
        return Ok(file_uri(&cache_file));
    }

    std::fs::create_dir_all(cache_dir).map_err(|_| ExtractError::Failed)?;
    let _apartment = ComApartment::initialize()?;
    let icon = shell_icon(executable_path, target_px).ok_or(ExtractError::NoIcon)?;
    let (width, height, pixels) = icon_pixels(icon.0).ok_or(ExtractError::Failed)?;
    write_png(&cache_file, width, height, &pixels)?;
    Ok(file_uri(&cache_file))
}

fn shell_icon(executable_path: &str, target_px: u32) -> Option<OwnedIcon> {
    let mut wide: Vec<u16> = executable_path.encode_utf16().collect();
    wide.push(0);
    let mut info = SHFILEINFOW::default();
    let size_flag = if target_px <= 16 {
        SHGFI_SMALLICON
    } else {
        SHGFI_LARGEICON
    };
    let result = unsafe {
        SHGetFileInfoW(
            wide.as_ptr(),
            0,
            &mut info,
            mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | size_flag,
        )
    };
    (result != 0 && !info.hIcon.is_null()).then_some(OwnedIcon(info.hIcon))
}

fn icon_pixels(
    icon: windows_sys::Win32::UI::WindowsAndMessaging::HICON,
) -> Option<(u32, u32, Vec<u8>)> {
    let mut info = ICONINFO::default();
    if unsafe { GetIconInfo(icon, &mut info) } == 0 {
        return None;
    }
    let color = OwnedBitmap(info.hbmColor);
    let mask = OwnedBitmap(info.hbmMask);
    if color.0.is_null() {
        return None;
    }

    let mut bitmap = BITMAP::default();
    let object_size = i32::try_from(mem::size_of::<BITMAP>()).ok()?;
    if unsafe { GetObjectW(color.0, object_size, (&mut bitmap as *mut BITMAP).cast()) } == 0 {
        return None;
    }
    let width = u32::try_from(bitmap.bmWidth).ok()?;
    let height = u32::try_from(bitmap.bmHeight).ok()?;
    if width == 0 || height == 0 {
        return None;
    }

    let mut bgra = read_bitmap(color.0, width, height)?;
    let has_alpha = bgra.chunks_exact(4).any(|pixel| pixel[3] != 0);
    let mask_pixels = (!has_alpha && !mask.0.is_null())
        .then(|| read_bitmap(mask.0, width, height))
        .flatten();

    for (index, pixel) in bgra.chunks_exact_mut(4).enumerate() {
        pixel.swap(0, 2);
        if !has_alpha {
            pixel[3] = mask_pixels.as_ref().map_or(255, |mask| {
                let mask_pixel = &mask[index * 4..index * 4 + 4];
                if mask_pixel[0] == 0 && mask_pixel[1] == 0 && mask_pixel[2] == 0 {
                    255
                } else {
                    0
                }
            });
        }
    }
    Some((width, height, bgra))
}

fn read_bitmap(
    bitmap: windows_sys::Win32::Graphics::Gdi::HBITMAP,
    width: u32,
    height: u32,
) -> Option<Vec<u8>> {
    let byte_count = usize::try_from(width)
        .ok()?
        .checked_mul(usize::try_from(height).ok()?)?
        .checked_mul(4)?;
    let mut pixels = vec![0u8; byte_count];
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: i32::try_from(width).ok()?,
            biHeight: -i32::try_from(height).ok()?,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..BITMAPINFOHEADER::default()
        },
        ..BITMAPINFO::default()
    };
    let dc = unsafe { GetDC(std::ptr::null_mut()) };
    if dc.is_null() {
        return None;
    }
    let scan_lines = unsafe {
        GetDIBits(
            dc,
            bitmap,
            0,
            height,
            pixels.as_mut_ptr().cast(),
            &mut info,
            DIB_RGB_COLORS,
        )
    };
    unsafe {
        ReleaseDC(std::ptr::null_mut(), dc);
    }
    (scan_lines == i32::try_from(height).ok()?).then_some(pixels)
}

fn write_png(path: &Path, width: u32, height: u32, pixels: &[u8]) -> Result<(), ExtractError> {
    let file = File::create(path).map_err(|_| ExtractError::Failed)?;
    let mut encoder = png::Encoder::new(BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(|_| ExtractError::Failed)?;
    writer
        .write_image_data(pixels)
        .map_err(|_| ExtractError::Failed)
}

fn file_uri(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let mut out = String::from("file:///");
    for byte in normalized.as_bytes() {
        match byte {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'/' | b':' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_file_uri_uses_forward_slashes_and_escapes_spaces() {
        assert_eq!(
            file_uri(Path::new(r"C:\Users\Test User\icon.png")),
            "file:///C:/Users/Test%20User/icon.png"
        );
    }

    #[test]
    fn extracts_an_executable_icon_to_a_cached_png() {
        let cache_dir = std::env::temp_dir().join(format!(
            "processtree-windows-icon-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&cache_dir);
        let executable = std::env::current_exe().expect("test executable");
        let uri = produce_icon(
            executable.to_str().expect("UTF-8 executable path"),
            &cache_dir,
            32,
        )
        .expect("Windows executable icon");

        assert!(uri.starts_with("file:///"));
        let cached = std::fs::read_dir(&cache_dir)
            .expect("cache directory")
            .next()
            .expect("cached icon")
            .expect("cached icon entry")
            .path();
        assert_eq!(
            cached.extension().and_then(|value| value.to_str()),
            Some("png")
        );
        assert!(std::fs::read(cached)
            .expect("cached PNG")
            .starts_with(b"\x89PNG\r\n\x1a\n"));
        let _ = std::fs::remove_dir_all(cache_dir);
    }
}
