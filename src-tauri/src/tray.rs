use anyhow::{Context, Result};
use tauri::{Emitter, Manager};

pub fn setup_tray(app: &tauri::AppHandle) -> Result<()> {
    // Use the existing app icon shipped by Tauri.
    let icon = tauri::include_image!("icons/icon.png");

    let (open_label, scan_label, about_label, quit_label) = tray_labels();

    let open_item =
        tauri::menu::MenuItem::with_id(app, "tray_open", open_label, true, None::<&str>)
            .with_context(|| format!("failed to create menu item '{}'", open_label))?;
    let scan_item =
        tauri::menu::MenuItem::with_id(app, "tray_scan", scan_label, true, None::<&str>)
            .with_context(|| format!("failed to create menu item '{}'", scan_label))?;
    let about_item =
        tauri::menu::MenuItem::with_id(app, "tray_about", about_label, true, None::<&str>)
            .with_context(|| format!("failed to create menu item '{}'", about_label))?;
    let quit_item =
        tauri::menu::MenuItem::with_id(app, "tray_quit", quit_label, true, None::<&str>)
            .with_context(|| format!("failed to create menu item '{}'", quit_label))?;

    let menu =
        tauri::menu::Menu::with_items(app, &[&open_item, &scan_item, &about_item, &quit_item])
            .with_context(|| "failed to create menu")?;

    let tray = tauri::tray::TrayIconBuilder::new()
        .icon(icon)
        .menu(&menu)
        .on_menu_event(|app: &tauri::AppHandle, event: tauri::menu::MenuEvent| {
            match event.id().as_ref() {
                "tray_open" => {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                }
                "tray_quit" => {
                    app.exit(0);
                }
                "tray_scan" => {
                    let _ = app.emit("pdd:tray", "scan");
                }
                "tray_about" => {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                    let _ = app.emit("pdd:tray", "about");
                }
                _ => {}
            }
        })
        .on_tray_icon_event(
            |tray: &tauri::tray::TrayIcon, event: tauri::tray::TrayIconEvent| {
                if let tauri::tray::TrayIconEvent::Click { .. } = event {
                    let app = tray.app_handle();
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                }
            },
        )
        .build(app)
        .with_context(|| "failed to build tray icon")?;

    // Keep tray alive.
    app.manage(tray);
    Ok(())
}

fn tray_labels() -> (&'static str, &'static str, &'static str, &'static str) {
    let lang = std::env::var("LANG").unwrap_or_default().to_lowercase();
    if lang.starts_with("fr") {
        return ("Ouvrir", "Scanner", "A propos", "Quitter");
    }
    if lang.starts_with("es") {
        return ("Abrir", "Escanear", "Acerca de", "Salir");
    }
    if lang.starts_with("de") {
        return ("Offnen", "Scannen", "Uber", "Beenden");
    }
    if lang.starts_with("ar") {
        return ("فتح", "فحص", "حول", "انهاء");
    }
    ("Open", "Scan", "About", "Quit")
}
