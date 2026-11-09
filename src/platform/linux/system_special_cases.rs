//! Exact Linux process patterns that carry application identity outside the
//! executable itself.
//!
//! Keep this module narrow. A rule belongs here only when a Linux system tool
//! publishes a documented, unambiguous application hint. Process ancestry,
//! child order, and current resource use are not identity signals.

use std::path::Path;

/// Returns the desktop-entry lookup source for a process. Direct shell scripts
/// name the launched application, while Bubblewrap's explicit `-- COMMAND`
/// form names the sandbox entrypoint when no exact cgroup identity is present.
pub(super) fn application_source<'a>(
    executable_path: &'a str,
    arguments: &'a [String],
    application_id: &str,
) -> &'a str {
    if matches!(executable_name(executable_path), "bash" | "dash" | "sh") {
        return shell_script_argument(arguments).unwrap_or(executable_path);
    }

    if executable_name(executable_path) != "bwrap" {
        return executable_path;
    }

    // Keep Bubblewrap as the lookup source when systemd supplies an
    // application ID. The icon resolver can then accept the ID only when the
    // matching desktop entry declares the same X-Flatpak value. Falling back
    // to the explicit command remains useful for launches without a cgroup ID.
    if !application_id.is_empty() {
        return executable_path;
    }

    arguments
        .iter()
        .position(|argument| argument == "--")
        .and_then(|separator| arguments.get(separator + 1))
        .map(String::as_str)
        .filter(|command| !command.is_empty() && *command != "--")
        .unwrap_or(executable_path)
}

fn shell_script_argument(arguments: &[String]) -> Option<&str> {
    let mut arguments = arguments.iter().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return arguments
                .next()
                .map(String::as_str)
                .filter(|path| !path.is_empty());
        }
        if argument == "-c" || argument == "-s" {
            return None;
        }
        if argument.starts_with('-') {
            continue;
        }
        return Some(argument.as_str());
    }
    None
}

/// Keeps the real wrapper name visible while adding the resolved application
/// name. Ordinary Linux application processes retain their resolved name.
pub(in crate::platform) fn display_name(
    process_name: &str,
    executable_path: &str,
    application_name: &str,
) -> String {
    if executable_name(executable_path) == "bwrap" && process_name != application_name {
        format!("{process_name} ({application_name})")
    } else {
        application_name.to_owned()
    }
}

fn executable_name(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::{application_source, display_name};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn bubblewrap_explicit_command_is_the_application_source() {
        let argv = arguments(&["/usr/bin/bwrap", "--args", "72", "--", "signal-desktop"]);

        assert_eq!(
            application_source("/usr/bin/bwrap", &argv, ""),
            "signal-desktop"
        );
    }

    #[test]
    fn bubblewrap_cgroup_identity_keeps_wrapper_as_the_lookup_source() {
        let argv = arguments(&["/usr/bin/bwrap", "--args", "73", "--", "bitwarden.sh"]);

        assert_eq!(
            application_source("/usr/bin/bwrap", &argv, "com.bitwarden.desktop"),
            "/usr/bin/bwrap"
        );
    }

    #[test]
    fn bubblewrap_rule_requires_an_explicit_nonempty_command() {
        let without_separator = arguments(&["/usr/bin/bwrap", "--args", "72"]);
        let without_command = arguments(&["/usr/bin/bwrap", "--"]);
        let another_process = arguments(&["/usr/bin/flatpak", "--", "signal-desktop"]);

        assert_eq!(
            application_source("/usr/bin/bwrap", &without_separator, ""),
            "/usr/bin/bwrap"
        );
        assert_eq!(
            application_source("/usr/bin/bwrap", &without_command, ""),
            "/usr/bin/bwrap"
        );
        assert_eq!(
            application_source("/usr/bin/flatpak", &another_process, ""),
            "/usr/bin/flatpak"
        );
    }

    #[test]
    fn direct_shell_script_is_the_application_source() {
        let brave = arguments(&["/bin/bash", "/usr/bin/brave-browser-stable"]);
        let options = arguments(&["/bin/sh", "-e", "--", "/usr/bin/application"]);

        assert_eq!(
            application_source("/usr/bin/bash", &brave, ""),
            "/usr/bin/brave-browser-stable"
        );
        assert_eq!(
            application_source("/usr/bin/dash", &options, ""),
            "/usr/bin/application"
        );
    }

    #[test]
    fn inline_shell_commands_are_not_application_sources() {
        let command = arguments(&["/bin/bash", "-c", "brave-browser-stable"]);
        let standard_input = arguments(&["/bin/sh", "-s", "brave-browser-stable"]);

        assert_eq!(application_source("/bin/bash", &command, ""), "/bin/bash");
        assert_eq!(
            application_source("/bin/sh", &standard_input, ""),
            "/bin/sh"
        );
    }

    #[test]
    fn resolved_bubblewrap_name_keeps_process_and_application_context() {
        assert_eq!(
            display_name("bwrap", "/usr/bin/bwrap", "Bitwarden"),
            "bwrap (Bitwarden)"
        );
        assert_eq!(
            display_name("bwrap", "/usr/bin/bwrap", "Signal Desktop"),
            "bwrap (Signal Desktop)"
        );
        assert_eq!(
            display_name("signal-desktop", "/app/signal-desktop", "Signal Desktop"),
            "Signal Desktop"
        );
    }
}
