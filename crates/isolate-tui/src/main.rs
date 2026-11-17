//! isolate-tui — Live ratatui TUI dashboard.
//!
//! Shows all active isoboxes with real-time:
//!   - Syscall frequency bar charts
//!   - Anomaly score gauges
//!   - Network connection maps
//!   - Alert feed

mod app;
mod events;
mod widgets;

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;

fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run app
    let result = run_app(&mut terminal);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> Result<()> {
    let mut app = app::App::new();

    loop {
        terminal.draw(|f| widgets::render(f, &app))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Tab => app.next_panel(),
                    KeyCode::Up | KeyCode::Char('k') => app.prev_isobox(),
                    KeyCode::Down | KeyCode::Char('j') => app.next_isobox(),
                    KeyCode::Char('f') => app.action_freeze(),
                    KeyCode::Char('t') => app.action_thaw(),
                    KeyCode::Char('x') => app.action_kill(), // 'k' = up; 'x' = kill
                    KeyCode::Char('?') => app.toggle_help(),
                    _ => {}
                }
            }
        }

        // Refresh data from isolatd REST API
        app.tick();
    }

    Ok(())
}
