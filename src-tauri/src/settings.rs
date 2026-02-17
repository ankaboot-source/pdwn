use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub watched_directories: Vec<String>,
    pub ignored_extensions: Vec<String>,
    pub max_file_bytes: u64,
    pub max_text_bytes: u64,
    pub max_zip_total_uncompressed_bytes: u64,
    pub max_zip_entry_bytes: u64,
    pub max_zip_entries: usize,
    pub max_zip_depth: usize,
    pub reminders_hours: i64,
    pub reminders_days_7: i64,
    pub reminders_days_30: i64,
}

impl Settings {
    pub fn default_from_os() -> Self {
        let mut watched = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Some(home) = dirs::home_dir() {
                if let Some(xdg_download) = linux_xdg_download_dir(&home) {
                    push_unique_dir(&mut watched, xdg_download);
                }
            }
        }

        if let Some(d) = dirs::download_dir() {
            push_unique_dir(&mut watched, d);
        } else if let Some(home) = dirs::home_dir() {
            push_unique_dir(&mut watched, home.join("Downloads"));
        }

        if watched.is_empty() {
            watched.push(".".to_string());
        }

        Self {
            watched_directories: watched,
            ignored_extensions: vec![
                ".crdownload".into(),
                ".part".into(),
                ".tmp".into(),
                ".download".into(),
            ],
            max_file_bytes: 150 * 1024 * 1024,
            max_text_bytes: 2 * 1024 * 1024,
            max_zip_total_uncompressed_bytes: 200 * 1024 * 1024,
            max_zip_entry_bytes: 50 * 1024 * 1024,
            max_zip_entries: 600,
            max_zip_depth: 2,
            reminders_hours: 24,
            reminders_days_7: 7,
            reminders_days_30: 30,
        }
    }

    pub fn watched_dirs(&self) -> Vec<PathBuf> {
        self.watched_directories.iter().map(PathBuf::from).collect()
    }

    pub fn is_ignored_extension(&self, path: &std::path::Path) -> bool {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        for ext in &self.ignored_extensions {
            if name.ends_with(ext) {
                return true;
            }
        }
        false
    }
}

fn push_unique_dir(target: &mut Vec<String>, dir: PathBuf) {
    let as_string = dir.to_string_lossy().to_string();
    if !target.contains(&as_string) {
        target.push(as_string);
    }
}

#[cfg(target_os = "linux")]
fn linux_xdg_download_dir(home: &std::path::Path) -> Option<PathBuf> {
    let user_dirs = home.join(".config").join("user-dirs.dirs");
    let content = std::fs::read_to_string(user_dirs).ok()?;
    parse_xdg_download_dir(&content, home)
}

#[cfg(target_os = "linux")]
fn parse_xdg_download_dir(content: &str, home: &std::path::Path) -> Option<PathBuf> {
    let home_str = home.to_string_lossy();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || !line.starts_with("XDG_DOWNLOAD_DIR=") {
            continue;
        }

        let mut value = line.split_once('=')?.1.trim().to_string();
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            value = value[1..value.len() - 1].to_string();
        }

        let expanded = value
            .replace("$HOME", &home_str)
            .replace("${HOME}", &home_str);

        if expanded.is_empty() {
            return None;
        }

        return Some(PathBuf::from(expanded));
    }

    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::parse_xdg_download_dir;
    use std::path::Path;

    #[test]
    fn parses_home_relative_downloads_dir() {
        let cfg = "XDG_DOWNLOAD_DIR=\"$HOME/Telechargements\"\n";
        let home = Path::new("/home/badreddine");
        let out = parse_xdg_download_dir(cfg, home);
        assert_eq!(out, Some(home.join("Telechargements")));
    }

    #[test]
    fn parses_absolute_downloads_dir() {
        let cfg = "XDG_DOWNLOAD_DIR=\"/mnt/data/downloads\"\n";
        let home = Path::new("/home/badreddine");
        let out = parse_xdg_download_dir(cfg, home);
        assert_eq!(out, Some(Path::new("/mnt/data/downloads").to_path_buf()));
    }

    #[test]
    fn ignores_comments_and_empty_lines() {
        let cfg = "# comment\n\nXDG_DOWNLOAD_DIR=\"${HOME}/Dl\"\n";
        let home = Path::new("/home/badreddine");
        let out = parse_xdg_download_dir(cfg, home);
        assert_eq!(out, Some(home.join("Dl")));
    }
}
