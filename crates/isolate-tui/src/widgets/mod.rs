use crate::app::{App, Panel};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        BarChart, Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap,
    },
    Frame,
};

pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();

    // Main layout: left panel (isobox list) | right panels
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    // Left: isobox list
    render_isobox_list(f, app, chunks[0]);

    // Right: split into top (syscall + anomaly) and bottom (alerts)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[1]);

    render_syscall_graph(f, app, right_chunks[0]);
    render_anomaly_gauge(f, app, right_chunks[1]);
    render_alert_feed(f, app, right_chunks[2]);

    // Render help overlay if toggled
    if app.show_help {
        render_help(f, area);
    }

    // Status bar
    render_status_bar(f, app, area);
}

fn render_isobox_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app.isoboxes.iter().enumerate().map(|(i, ib)| {
        let anomaly = ib.anomaly_score.map(|s| format!(" {:.2}", s)).unwrap_or_default();
        let alert_badge = if ib.alert_count.unwrap_or(0) > 0 {
            format!(" [{}!]", ib.alert_count.unwrap_or(0))
        } else {
            String::new()
        };

        let status_color = match ib.state.as_str() {
            "running" if ib.anomaly_score.unwrap_or(0.0) > 0.75 => Color::Red,
            "running" => Color::Green,
            "frozen" => Color::Yellow,
            _ => Color::Gray,
        };

        let content = Line::from(vec![
            Span::styled("● ", Style::default().fg(status_color)),
            Span::raw(format!("{:<18}", &ib.name[..ib.name.len().min(18)])),
            Span::styled(anomaly, Style::default().fg(if ib.anomaly_score.unwrap_or(0.0) > 0.75 {
                Color::Red
            } else {
                Color::Gray
            })),
            Span::styled(alert_badge, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        ]);

        ListItem::new(content)
    }).collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" ISOBOXES ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    let mut state = ListState::default();
    state.select(Some(app.selected_isobox));
    f.render_stateful_widget(list, area, &mut state);
}

fn render_syscall_graph(f: &mut Frame, app: &App, area: Rect) {
    // Synthetic syscall data (replace with real data from API in Phase 4)
    let data: Vec<(&str, u64)> = vec![
        ("open", 1240),
        ("read", 892),
        ("write", 310),
        ("stat", 640),
        ("mmap", 152),
        ("close", 780),
        ("exec", 47),
        ("fork", 3),
    ];

    let chart = BarChart::default()
        .block(
            Block::default()
                .title(format!(
                    " SYSCALLS  {} ",
                    app.selected().map(|ib| ib.name.as_str()).unwrap_or("-")
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .data(&data)
        .bar_width(6)
        .bar_gap(1)
        .bar_style(Style::default().fg(Color::Cyan))
        .value_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
        .label_style(Style::default().fg(Color::Gray));

    f.render_widget(chart, area);
}

fn render_anomaly_gauge(f: &mut Frame, app: &App, area: Rect) {
    let score = app.selected()
        .and_then(|ib| ib.anomaly_score)
        .unwrap_or(0.0);

    let (color, label) = if score >= 0.90 {
        (Color::Red, "CRITICAL")
    } else if score >= 0.75 {
        (Color::LightRed, "WARNING")
    } else if score >= 0.50 {
        (Color::Yellow, "ELEVATED")
    } else {
        (Color::Green, "NORMAL")
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(format!(" ANOMALY SCORE  {}  threshold:0.75 ", label))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(color)),
        )
        .gauge_style(Style::default().fg(color))
        .ratio(score as f64)
        .label(format!("{:.0}%", score * 100.0));

    f.render_widget(gauge, area);
}

fn render_alert_feed(f: &mut Frame, app: &App, area: Rect) {
    let placeholder_alerts = vec![
        Line::from(vec![
            Span::styled("[CRITICAL] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw("IOC match: 192.168.1.100:4444 — C2 port (ThreatFox 92%)"),
        ]),
        Line::from(vec![
            Span::styled("[WARN]     ", Style::default().fg(Color::Yellow)),
            Span::raw("Anomaly score 0.82 — execve spike: 47 processes in 10s"),
        ]),
        Line::from(vec![
            Span::styled("[INFO]     ", Style::default().fg(Color::Blue)),
            Span::raw("Baseline warm for dev-env (workload_class: dev-environment)"),
        ]),
    ];

    let para = Paragraph::new(placeholder_alerts)
        .block(
            Block::default()
                .title(" ALERT FEED ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(para, area);
}

fn render_help(f: &mut Frame, area: Rect) {
    let help_text = Paragraph::new(vec![
        Line::from("  Keyboard shortcuts"),
        Line::from("  ─────────────────────────────────────"),
        Line::from("  Tab        Switch panel"),
        Line::from("  j/↓        Next isobox"),
        Line::from("  k/↑        Previous isobox"),
        Line::from("  f          Freeze selected isobox"),
        Line::from("  t          Thaw selected isobox"),
        Line::from("  k          Kill selected isobox"),
        Line::from("  e          Export forensic bundle"),
        Line::from("  q          Quit"),
        Line::from("  ?          Toggle this help"),
    ])
    .block(
        Block::default()
            .title(" HELP ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White)),
    );

    // Center the help overlay
    let help_area = Rect {
        x: area.width / 4,
        y: area.height / 4,
        width: area.width / 2,
        height: area.height / 2,
    };
    f.render_widget(ratatui::widgets::Clear, help_area);
    f.render_widget(help_text, help_area);
}

fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    // Status bar at the bottom — rendered over existing content as an overlay
    let status = format!(
        " isolate v0.1.0  │  {} isoboxes  │  [Tab] panel  [?] help  [q] quit ",
        app.isoboxes.len()
    );
    let bar = Paragraph::new(status)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));

    let bar_area = Rect {
        x: 0,
        y: area.height.saturating_sub(1),
        width: area.width,
        height: 1,
    };
    f.render_widget(bar, bar_area);
}
