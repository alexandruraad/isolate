// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;
mod ws;

use state::AppState;
use tauri::{Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, CustomMenuItem};
use tracing::info;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("isolate_ui=debug".parse().unwrap())
        )
        .init();

    info!("isolate-ui starting");

    let tray_menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("open", "Open Dashboard"))
        .add_item(CustomMenuItem::new("quit", "Quit isolate"));

    let tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .system_tray(tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { .. } => {
                if let Some(w) = app.get_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "open" => {
                    if let Some(w) = app.get_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                }
                "quit" => std::process::exit(0),
                _ => {}
            },
            _ => {}
        })
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::list_isoboxes,
            commands::get_isobox,
            commands::create_isobox,
            commands::stop_isobox,
            commands::freeze_isobox,
            commands::thaw_isobox,
            commands::snapshot_isobox,
            commands::get_policy,
            commands::apply_policy,
            commands::list_alerts,
            commands::list_feeds,
            commands::update_feeds,
            commands::get_health,
            commands::set_daemon_url,
        ])
        .setup(|app| {
            // Start the WebSocket event relay
            let app_handle = app.handle();
            let state: tauri::State<AppState> = app.state();
            let ws_url = state.ws_url();
            ws::spawn_relay(app_handle, ws_url);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running isolate-ui");
}
