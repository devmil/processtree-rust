use std::cmp::Reverse;
use std::fs;
use std::path::{Path, PathBuf};

use super::file_uri;

pub struct ResolvedApplication {
    pub name: String,
    pub icon_uri: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct DesktopEntry {
    name: String,
    desktop_id: String,
    flatpak_id: Option<String>,
    renamed_desktop_ids: Vec<String>,
    executable: String,
    canonical_executable: Option<PathBuf>,
    startup_wm_class: String,
    icon: Option<String>,
}

pub(super) struct IconResolver {
    data_dirs: Vec<PathBuf>,
    desktop_entries: Vec<DesktopEntry>,
    themes: Vec<String>,
}

struct ResolvedEntry<'a> {
    name: &'a str,
    icon_path: Option<PathBuf>,
}

impl IconResolver {
    pub(super) fn from_environment() -> Self {
        let data_dirs = freedesktop_data_dirs();
        Self::from_data_dirs(data_dirs, configured_icon_themes())
    }

    pub(super) fn from_data_dirs(data_dirs: Vec<PathBuf>, themes: Vec<String>) -> Self {
        let mut desktop_entries = Vec::new();
        let localized_name_keys = localized_name_keys();
        for data_dir in &data_dirs {
            collect_desktop_entries(
                &data_dir.join("applications"),
                &mut desktop_entries,
                &localized_name_keys,
                0,
            );
        }
        Self {
            data_dirs,
            desktop_entries,
            themes,
        }
    }

    /// Reload installed desktop metadata on the background worker. A changed
    /// catalog invalidates both successful and unsuccessful source lookups.
    pub(super) fn refresh(&mut self) -> bool {
        let updated = Self::from_data_dirs(self.data_dirs.clone(), self.themes.clone());
        if self.desktop_entries == updated.desktop_entries {
            return false;
        }
        self.desktop_entries = updated.desktop_entries;
        true
    }

    pub(super) fn resolve_application(
        &self,
        source: &str,
        application_id: &str,
        target_px: u32,
    ) -> Option<ResolvedApplication> {
        let resolved = self.resolve(source, application_id, target_px)?;
        Some(ResolvedApplication {
            name: resolved.name.to_string(),
            icon_uri: resolved.icon_path.as_ref().map(|path| file_uri(path)),
        })
    }

    fn resolve(
        &self,
        source: &str,
        application_id: &str,
        target_px: u32,
    ) -> Option<ResolvedEntry<'_>> {
        let source_path = Path::new(source);
        let source_canonical = fs::canonicalize(source_path).ok();
        let source_name = source_path
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_default();
        let source_name = source_name.trim_end_matches(" (deleted)");
        let entry = if let Some(entry) = self.desktop_entry_by_id(application_id).filter(|entry| {
            source_name.is_empty()
                || entry_score(entry, source_path, source_canonical.as_deref(), source_name) > 0
                || (source_name == "bwrap" && entry.flatpak_id.as_deref() == Some(application_id))
        }) {
            entry
        } else {
            if source_name.is_empty() {
                return None;
            }
            self.desktop_entries
                .iter()
                .filter_map(|entry| {
                    let score =
                        entry_score(entry, source_path, source_canonical.as_deref(), source_name);
                    (score > 0).then_some((score, entry))
                })
                .max_by_key(|(score, _)| *score)
                .map(|(_, entry)| entry)?
        };

        Some(ResolvedEntry {
            name: &entry.name,
            icon_path: entry
                .icon
                .as_deref()
                .and_then(|icon| self.resolve_icon_name(icon, target_px)),
        })
    }

    fn desktop_entry_by_id(&self, application_id: &str) -> Option<&DesktopEntry> {
        if application_id.is_empty() {
            return None;
        }
        let desktop_id = format!("{application_id}.desktop");
        self.desktop_entries
            .iter()
            .find(|entry| entry.desktop_id == application_id || entry.desktop_id == desktop_id)
    }

    fn resolve_icon_name(&self, icon: &str, target_px: u32) -> Option<PathBuf> {
        let icon_path = Path::new(icon);
        if icon_path.is_absolute() && icon_path.is_file() {
            return Some(icon_path.to_path_buf());
        }

        let icon_name = icon
            .strip_suffix(".png")
            .or_else(|| icon.strip_suffix(".svg"))
            .or_else(|| icon.strip_suffix(".xpm"))
            .unwrap_or(icon);
        let mut sizes = vec![target_px, 256, 128, 512, 64, 48, 32, 24, 22, 16];
        sizes.sort_unstable();
        sizes.dedup();
        sizes.sort_by_key(|size| (size.abs_diff(target_px), Reverse(*size)));

        for data_dir in &self.data_dirs {
            for theme in &self.themes {
                let root = data_dir.join("icons").join(theme);
                for size in &sizes {
                    for directory in [
                        root.join("apps").join(size.to_string()),
                        root.join(format!("{size}x{size}")).join("apps"),
                    ] {
                        if let Some(path) = icon_file_in(&directory, icon_name) {
                            return Some(path);
                        }
                    }
                }
                if let Some(path) = icon_file_in(&root.join("scalable/apps"), icon_name) {
                    return Some(path);
                }
            }
            if let Some(path) = icon_file_in(&data_dir.join("pixmaps"), icon_name) {
                return Some(path);
            }
        }
        None
    }
}

fn entry_score(
    entry: &DesktopEntry,
    source_path: &Path,
    source_canonical: Option<&Path>,
    source_name: &str,
) -> u16 {
    let executable_path = Path::new(&entry.executable);
    let executable_name = executable_path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();

    if source_canonical.is_some() && entry.canonical_executable.as_deref() == source_canonical {
        return 1000;
    }
    if executable_path.is_absolute() && executable_path == source_path {
        return 950;
    }
    if executable_name == source_name {
        return 900;
    }
    if entry.startup_wm_class.eq_ignore_ascii_case(source_name) {
        return 850;
    }

    let desktop_id = entry.desktop_id.to_ascii_lowercase();
    let source_lower = source_name.to_ascii_lowercase();
    if desktop_id == source_lower || desktop_id == format!("{source_lower}.desktop") {
        return 800;
    }
    if desktop_id
        .strip_suffix(".desktop")
        .is_some_and(|id| id.ends_with(&format!(".{source_lower}")))
    {
        return 780;
    }
    if entry
        .renamed_desktop_ids
        .iter()
        .any(|desktop_id| desktop_alias_matches_source(desktop_id, &source_lower))
    {
        return 770;
    }

    if source_lower.len() >= 4 {
        let executable_lower = executable_name.to_ascii_lowercase();
        let wm_class = entry.startup_wm_class.to_ascii_lowercase();
        if executable_lower.starts_with(&format!("{source_lower}-"))
            || executable_lower.starts_with(&format!("{source_lower}_"))
        {
            return if wm_class.starts_with(&source_lower) {
                700
            } else {
                600
            };
        }
        if desktop_id.contains(&source_lower) && wm_class.starts_with(&source_lower) {
            return 650;
        }
    }
    0
}

fn desktop_alias_matches_source(desktop_id: &str, source: &str) -> bool {
    let desktop_id = desktop_id.to_ascii_lowercase();
    let alias = desktop_id.strip_suffix(".desktop").unwrap_or(&desktop_id);
    alias.len() >= 4
        && (source == alias
            || source.starts_with(&format!("{alias}-"))
            || source.starts_with(&format!("{alias}_")))
}

fn collect_desktop_entries(
    directory: &Path,
    entries: &mut Vec<DesktopEntry>,
    localized_name_keys: &[String],
    depth: u8,
) {
    if depth > 3 {
        return;
    }
    let Ok(children) = fs::read_dir(directory) else {
        return;
    };
    let mut children = children.flatten().collect::<Vec<_>>();
    children.sort_by_key(|child| child.path());
    for child in children {
        let path = child.path();
        if path.is_dir() {
            collect_desktop_entries(&path, entries, localized_name_keys, depth + 1);
        } else if path.extension().and_then(|value| value.to_str()) == Some("desktop") {
            if let Some(entry) = parse_desktop_entry(&path, localized_name_keys) {
                entries.push(entry);
            }
        }
    }
}

fn parse_desktop_entry(path: &Path, localized_name_keys: &[String]) -> Option<DesktopEntry> {
    let text = fs::read_to_string(path).ok()?;
    let mut in_desktop_entry = false;
    let mut exec = None;
    let mut try_exec = None;
    let mut icon = None;
    let mut startup_wm_class = String::new();
    let mut flatpak_id = None;
    let mut renamed_desktop_ids = Vec::new();
    let mut localized_name: Option<(usize, String)> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == "[Desktop Entry]" {
            in_desktop_entry = true;
            continue;
        }
        if line.starts_with('[') {
            if in_desktop_entry {
                break;
            }
            continue;
        }
        if !in_desktop_entry || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Exec" => exec = first_exec_program(value),
            "TryExec" => try_exec = first_exec_program(value),
            "Icon" => icon = Some(value.trim().to_string()),
            "StartupWMClass" => startup_wm_class = value.trim().to_string(),
            "X-Flatpak" => flatpak_id = Some(value.trim().to_string()),
            "X-Flatpak-RenamedFrom" => {
                renamed_desktop_ids.extend(
                    value
                        .split(';')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned),
                );
            }
            _ => {
                if let Some(priority) = localized_name_keys
                    .iter()
                    .position(|candidate| candidate == key)
                {
                    if localized_name
                        .as_ref()
                        .is_none_or(|(current, _)| priority < *current)
                    {
                        localized_name = Some((priority, value.trim().to_string()));
                    }
                }
            }
        }
    }
    let executable = exec.or(try_exec)?;
    let icon = icon.filter(|value| !value.is_empty());
    let name = localized_name
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())?;
    let resolved_executable = resolve_executable(&executable);
    Some(DesktopEntry {
        name,
        desktop_id: path.file_name()?.to_string_lossy().into_owned(),
        flatpak_id: flatpak_id.filter(|value| !value.is_empty()),
        renamed_desktop_ids,
        canonical_executable: resolved_executable
            .as_deref()
            .and_then(|value| fs::canonicalize(value).ok()),
        executable: resolved_executable
            .unwrap_or_else(|| PathBuf::from(&executable))
            .to_string_lossy()
            .into_owned(),
        startup_wm_class,
        icon,
    })
}

fn localized_name_keys() -> Vec<String> {
    let locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()));
    let mut keys = Vec::new();
    if let Some(locale) = locale {
        let locale = locale.split('.').next().unwrap_or(&locale);
        if !matches!(locale, "C" | "POSIX") {
            keys.push(format!("Name[{locale}]"));
            let language = locale.split(['_', '@']).next().unwrap_or(locale);
            let language_key = format!("Name[{language}]");
            if !keys.contains(&language_key) {
                keys.push(language_key);
            }
        }
    }
    keys.push("Name".to_string());
    keys
}

fn first_exec_program(value: &str) -> Option<String> {
    let tokens = shell_tokens(value);
    let mut index = 0;
    if tokens.first().map(String::as_str) == Some("env") {
        index += 1;
        while tokens
            .get(index)
            .is_some_and(|token| token.starts_with('-') || token.contains('='))
        {
            index += 1;
        }
    }
    tokens
        .get(index)
        .filter(|token| !token.starts_with('%'))
        .cloned()
}

fn shell_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            token.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                token.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(character);
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

fn resolve_executable(executable: &str) -> Option<PathBuf> {
    let path = Path::new(executable);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    std::env::var_os("PATH")?
        .to_string_lossy()
        .split(':')
        .map(Path::new)
        .map(|directory| directory.join(executable))
        .find(|candidate| candidate.is_file())
}

fn icon_file_in(directory: &Path, icon_name: &str) -> Option<PathBuf> {
    ["png", "svg", "xpm"]
        .into_iter()
        .map(|extension| directory.join(format!("{icon_name}.{extension}")))
        .find(|candidate| candidate.is_file())
}

fn freedesktop_data_dirs() -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        directories.push(PathBuf::from(data_home));
    } else if let Some(home) = std::env::var_os("HOME") {
        directories.push(PathBuf::from(home).join(".local/share"));
    }
    let system = std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".to_string());
    directories.extend(
        system
            .split(':')
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
    );
    directories
}

fn configured_icon_themes() -> Vec<String> {
    let mut themes = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(home).join(".config"));
        if let Ok(text) = fs::read_to_string(config_home.join("kdeglobals")) {
            let mut in_icons = false;
            for line in text.lines().map(str::trim) {
                if line == "[Icons]" {
                    in_icons = true;
                } else if line.starts_with('[') {
                    in_icons = false;
                } else if in_icons {
                    if let Some(theme) = line.strip_prefix("Theme=") {
                        themes.push(theme.trim().to_string());
                    }
                }
            }
        }
    }
    for fallback in ["hicolor", "breeze", "breeze-dark", "oxygen", "Adwaita"] {
        if !themes.iter().any(|theme| theme == fallback) {
            themes.push(fallback.to_string());
        }
    }
    themes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_installed_changed_and_removed_applications() {
        let root = std::env::temp_dir().join(format!("processtree-refresh-{}", std::process::id()));
        let applications = root.join("applications");
        let icons = root.join("icons/hicolor/scalable/apps");
        fs::create_dir_all(&applications).unwrap();
        fs::create_dir_all(&icons).unwrap();
        let mut resolver = IconResolver::from_data_dirs(vec![root.clone()], vec!["hicolor".into()]);
        assert!(resolver
            .resolve_application("/opt/maillama/maillama", "de.devmil.maillama", 128)
            .is_none());
        assert!(!resolver.refresh());

        let desktop = applications.join("de.devmil.maillama.desktop");
        fs::write(&desktop, "[Desktop Entry]\nName=MailLama\nExec=maillama %U\nIcon=de.devmil.maillama\nStartupWMClass=de.devmil.maillama\n").unwrap();
        let icon = icons.join("de.devmil.maillama.svg");
        fs::write(&icon, "<svg/>").unwrap();
        assert!(resolver.refresh());
        let resolved = resolver
            .resolve_application("/opt/maillama/maillama", "de.devmil.maillama", 128)
            .unwrap();
        assert_eq!(resolved.name, "MailLama");
        assert_eq!(resolved.icon_uri, Some(file_uri(&icon)));
        assert!(!resolver.refresh());

        fs::write(
            &desktop,
            "[Desktop Entry]\nName=Renamed App\nExec=maillama %U\n",
        )
        .unwrap();
        assert!(resolver.refresh());
        assert_eq!(
            resolver
                .resolve_application("/opt/maillama/maillama", "de.devmil.maillama", 128)
                .unwrap()
                .name,
            "Renamed App"
        );
        fs::remove_file(&desktop).unwrap();
        assert!(resolver.refresh());
        assert!(resolver
            .resolve_application("/opt/maillama/maillama", "de.devmil.maillama", 128)
            .is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_quoted_desktop_exec_program() {
        assert_eq!(
            first_exec_program("env FOO=bar \"/opt/My App/app\" --flag %U").as_deref(),
            Some("/opt/My App/app")
        );
    }

    #[test]
    fn matches_reverse_domain_desktop_id_to_executable_name() {
        let entry = DesktopEntry {
            name: "Mimameidr".to_string(),
            desktop_id: "de.devmil.mimameidr.desktop".to_string(),
            flatpak_id: None,
            renamed_desktop_ids: Vec::new(),
            executable: "/usr/bin/installed-wrapper".to_string(),
            canonical_executable: None,
            startup_wm_class: "de.devmil.mimameidr".to_string(),
            icon: Some("de.devmil.mimameidr".to_string()),
        };

        assert_eq!(
            entry_score(
                &entry,
                Path::new("/tmp/bundle/mimameidr"),
                None,
                "mimameidr",
            ),
            780,
        );
    }

    #[test]
    fn resolves_flatpak_renamed_desktop_id_to_sandbox_executable() {
        let root =
            std::env::temp_dir().join(format!("processtree-linux-flatpak-{}", std::process::id()));
        let applications = root.join("applications");
        let icons = root.join("icons/hicolor/128x128/apps");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&applications).unwrap();
        fs::create_dir_all(&icons).unwrap();
        fs::write(
            applications.join("com.bitwarden.desktop.desktop"),
            "[Desktop Entry]\nName=Bitwarden\nExec=/usr/bin/flatpak run --command=bitwarden.sh com.bitwarden.desktop\nIcon=com.bitwarden.desktop\nStartupWMClass=com.bitwarden.desktop\nX-Flatpak-RenamedFrom=bitwarden.desktop;\nX-Flatpak=com.bitwarden.desktop\n",
        )
        .unwrap();
        fs::write(
            applications.join("org.example.Native.desktop"),
            "[Desktop Entry]\nName=Native App\nExec=/opt/native-app\nIcon=native-app\n",
        )
        .unwrap();
        fs::write(icons.join("com.bitwarden.desktop.png"), b"png").unwrap();

        let resolver =
            IconResolver::from_data_dirs(vec![root.clone()], vec!["hicolor".to_string()]);
        let resolved = resolver
            .resolve("/app/Bitwarden/bitwarden-app", "com.bitwarden.desktop", 128)
            .unwrap();
        assert_eq!(resolved.name, "Bitwarden");
        assert_eq!(
            resolved.icon_path,
            Some(icons.join("com.bitwarden.desktop.png"))
        );
        let wrapper = resolver
            .resolve("/usr/bin/bwrap", "com.bitwarden.desktop", 128)
            .unwrap();
        assert_eq!(wrapper.name, "Bitwarden");
        assert_eq!(
            wrapper.icon_path,
            Some(icons.join("com.bitwarden.desktop.png"))
        );
        assert!(resolver
            .resolve("/usr/bin/cat", "com.bitwarden.desktop", 128)
            .is_none());
        assert!(resolver
            .resolve("/usr/bin/bwrap", "org.example.Native", 128)
            .is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn prefers_localized_desktop_name() {
        let root =
            std::env::temp_dir().join(format!("processtree-linux-name-{}", std::process::id()));
        let desktop = root.join("example.desktop");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            &desktop,
            "[Desktop Entry]\nName=Example App\nName[de]=Beispiel-App\nExec=example\nIcon=example\n",
        )
        .unwrap();

        let entry = parse_desktop_entry(
            &desktop,
            &[
                "Name[de_DE]".to_string(),
                "Name[de]".to_string(),
                "Name".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(entry.name, "Beispiel-App");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resolves_desktop_entry_to_hicolor_icon() {
        let root =
            std::env::temp_dir().join(format!("processtree-linux-icons-{}", std::process::id()));
        let applications = root.join("applications");
        let icons = root.join("icons/hicolor/128x128/apps");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&applications).unwrap();
        fs::create_dir_all(&icons).unwrap();
        fs::write(
            applications.join("example.desktop"),
            "[Desktop Entry]\nName=Example App\nExec=/opt/example/bin/example %U\nIcon=example\n",
        )
        .unwrap();
        fs::write(icons.join("example.png"), b"png").unwrap();

        let resolver =
            IconResolver::from_data_dirs(vec![root.clone()], vec!["hicolor".to_string()]);
        let resolved = resolver
            .resolve("/opt/example/bin/example", "", 128)
            .unwrap();
        assert_eq!(resolved.name, "Example App");
        assert_eq!(resolved.icon_path, Some(icons.join("example.png")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn desktop_application_id_wins_over_shared_executable_name() {
        let root =
            std::env::temp_dir().join(format!("processtree-linux-app-id-{}", std::process::id()));
        let applications = root.join("applications");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&applications).unwrap();
        fs::write(
            applications.join("org.example.First.desktop"),
            "[Desktop Entry]\nName=First App\nExec=/opt/shared/runtime\nIcon=first\n",
        )
        .unwrap();
        fs::write(
            applications.join("org.example.Second.desktop"),
            "[Desktop Entry]\nName=Second App\nExec=/opt/shared/runtime\nIcon=second\n",
        )
        .unwrap();

        let resolver = IconResolver::from_data_dirs(vec![root.clone()], vec!["hicolor".into()]);
        let resolved = resolver
            .resolve("/opt/shared/runtime", "org.example.Second", 128)
            .unwrap();
        assert_eq!(resolved.name, "Second App");

        let resolved_without_executable = resolver.resolve("", "org.example.Second", 128).unwrap();
        assert_eq!(resolved_without_executable.name, "Second App");

        assert!(resolver
            .resolve("/usr/bin/cat", "org.example.Second", 128)
            .is_none());

        let _ = fs::remove_dir_all(root);
    }
}
