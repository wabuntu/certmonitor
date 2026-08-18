mod scan;
mod web;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState};
use scan::{
    CertResult, Severity, Status, Target, check_all, check_all_async, parse_target, severity,
};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// TUI that ranks a list of host:port targets by days until their TLS
/// certificate expires, like `top` for certificate expiry.
#[derive(Parser, Debug)]
#[clap(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    about = env!("CARGO_PKG_DESCRIPTION"),
)]
struct Args {
    /// Path to a text file listing targets, one per line, as `host` or
    /// `host:port` (bare hosts default to port 443). Blank lines and lines
    /// starting with `#` are ignored.
    targets_file: PathBuf,

    /// Path to a TOML config file for the settings below, so they don't
    /// need to be repeated on every invocation (handy for a systemd timer).
    /// Defaults to `~/.config/certmonitor/config.toml` if present; it's not
    /// an error for that default path to be missing. A flag on the command
    /// line always overrides the same setting in the config file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Per-target connect + TLS handshake timeout, in seconds. Default: 5.
    #[arg(long)]
    timeout: Option<u64>,

    /// Certificates with fewer days left than this are shown in yellow.
    /// Default: 30.
    #[arg(long)]
    warn_days: Option<i64>,

    /// Certificates with fewer days left than this (or already expired) are
    /// shown in red. Default: 7.
    #[arg(long)]
    critical_days: Option<i64>,

    /// Automatically rescan every N seconds. Without this, press `r` to
    /// rescan manually.
    #[arg(long)]
    interval: Option<u64>,

    /// Run a single scan, print a plain-text report to stdout, and exit —
    /// no TUI. Exit code follows the Nagios convention (0 = OK, 1 = a
    /// warning-level cert, 2 = a critical/expired cert or a check that
    /// failed outright), so this is meant to be run from a systemd timer or
    /// cron job with alerting wired up via `OnFailure=` / the job runner's
    /// own failure notifications.
    #[arg(long)]
    once: bool,

    /// Serve an auto-refreshing HTML page of the same table at this
    /// address (e.g. `0.0.0.0:8080`) instead of showing the TUI. Rescans
    /// every `--interval` seconds in the background (default 300);
    /// requests are always answered from the latest finished scan.
    #[arg(long)]
    serve: Option<String>,
}

/// Every field is optional, so a config file only needs to set what it
/// wants to override.
#[derive(serde::Deserialize, Default)]
struct FileConfig {
    timeout: Option<u64>,
    warn_days: Option<i64>,
    critical_days: Option<i64>,
    interval: Option<u64>,
}

/// Load `explicit_path`, or `~/.config/certmonitor/config.toml` if none was
/// given. A missing file at the *default* path is not an error (most users
/// won't have one); a missing or unparseable file at an *explicitly*
/// requested path is, since the user asked for that file by name.
fn load_config(explicit_path: &Option<PathBuf>) -> FileConfig {
    let (path, required) = match explicit_path {
        Some(p) => (p.clone(), true),
        None => {
            let home = std::env::var("HOME").unwrap_or_default();
            (
                PathBuf::from(home).join(".config/certmonitor/config.toml"),
                false,
            )
        }
    };

    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            eprintln!(
                "Error: failed to parse config file {}: {}",
                path.display(),
                e
            );
            std::process::exit(1);
        }),
        Err(_) if required => {
            eprintln!("Error: config file {} not found", path.display());
            std::process::exit(1);
        }
        Err(_) => FileConfig::default(),
    }
}

struct App {
    results: Vec<CertResult>,
    table_state: TableState,
    warn_days: i64,
    critical_days: i64,
    last_scan: Option<Instant>,
    /// Index into `results` currently shown in the detail popup, if any.
    show_detail: Option<usize>,
}

impl App {
    fn new(warn_days: i64, critical_days: i64) -> App {
        App {
            results: Vec::new(),
            table_state: TableState::default(),
            warn_days,
            critical_days,
            last_scan: None,
            show_detail: None,
        }
    }

    fn set_results(&mut self, results: Vec<CertResult>) {
        self.results = results;
        self.last_scan = Some(Instant::now());
        if self.table_state.selected().is_none() && !self.results.is_empty() {
            self.table_state.select(Some(0));
        }
    }

    fn move_selection(&mut self, forward: bool) {
        if self.results.is_empty() {
            return;
        }
        let len = self.results.len();
        let i = self.table_state.selected().unwrap_or(0);
        let next = if forward {
            (i + 1) % len
        } else {
            (i + len - 1) % len
        };
        self.table_state.select(Some(next));
    }

    fn row_color(&self, result: &CertResult) -> Color {
        match severity(result, self.warn_days, self.critical_days) {
            Severity::Critical => Color::Red,
            Severity::Warning => Color::Yellow,
            Severity::Ok => Color::Green,
        }
    }
}

fn main() {
    let args = Args::parse();

    let text = std::fs::read_to_string(&args.targets_file).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {}", args.targets_file.display(), e);
        std::process::exit(1);
    });
    let targets: Vec<Target> = text.lines().filter_map(parse_target).collect();
    if targets.is_empty() {
        eprintln!(
            "No targets found in {} (expected one `host` or `host:port` per line).",
            args.targets_file.display()
        );
        std::process::exit(1);
    }

    let file_config = load_config(&args.config);
    let timeout = Duration::from_secs(args.timeout.or(file_config.timeout).unwrap_or(5));
    let warn_days = args.warn_days.or(file_config.warn_days).unwrap_or(30);
    let critical_days = args
        .critical_days
        .or(file_config.critical_days)
        .unwrap_or(7);
    let interval = args.interval.or(file_config.interval);

    if args.once {
        std::process::exit(run_once(&targets, timeout, warn_days, critical_days));
    }

    if let Some(addr) = &args.serve {
        let interval = interval.unwrap_or(300);
        if let Err(e) = web::serve(addr, targets, timeout, warn_days, critical_days, interval) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let mut app = App::new(warn_days, critical_days);

    eprintln!("Scanning {} targets ...", targets.len());
    let (handle, progress) = check_all_async(targets.clone(), timeout);
    while !handle.is_finished() {
        let n = progress.load(Ordering::Relaxed);
        eprint!("\r  {}/{} checked so far...", n, targets.len());
        let _ = std::io::stderr().flush();
        std::thread::sleep(Duration::from_millis(120));
    }
    eprintln!("\r  Scan complete.                              ");
    app.set_results(handle.join().expect("scan thread panicked"));

    let mut terminal = ratatui::init();
    let res = run(&mut terminal, &mut app, targets, timeout, interval);
    ratatui::restore();

    if let Err(e) = res {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Run one scan, print a report to stdout, and return a Nagios-style exit
/// code (0 OK, 1 warning, 2 critical) — meant for cron/systemd timers as
/// much as for a human running it directly. Output is a plain, aligned
/// table; when stdout is an actual terminal, the status column is also
/// colored (never when piped/redirected, so logs stay clean of ANSI codes).
fn run_once(targets: &[Target], timeout: Duration, warn_days: i64, critical_days: i64) -> i32 {
    use std::io::IsTerminal;
    let colorize = std::io::stdout().is_terminal();

    eprintln!("Scanning {} targets ...", targets.len());
    let results = check_all(targets, timeout);

    struct Row {
        label: &'static str,
        severity: Severity,
        target: String,
        days: String,
        expires: String,
        hint: String,
    }

    let rows: Vec<Row> = results
        .iter()
        .map(|r| {
            let severity = severity(r, warn_days, critical_days);
            Row {
                label: match severity {
                    Severity::Ok => "OK",
                    Severity::Warning => "WARNING",
                    Severity::Critical => "CRITICAL",
                },
                severity,
                target: format!("{}:{}", r.target.host, r.target.port),
                days: match r.status {
                    Status::Ok(days) if days < 0 => format!("expired {}d ago", -days),
                    Status::Ok(days) => format!("{}d", days),
                    Status::Error(_) => "-".to_string(),
                },
                expires: r.not_after.clone().unwrap_or_else(|| "-".to_string()),
                hint: match &r.status {
                    Status::Error(e) => e.clone(),
                    Status::Ok(_) => r.renewal_hint().to_string(),
                },
            }
        })
        .collect();

    let target_w = rows
        .iter()
        .map(|r| r.target.len())
        .max()
        .unwrap_or(0)
        .max(6);
    let days_w = rows.iter().map(|r| r.days.len()).max().unwrap_or(0).max(9);
    let expires_w = rows
        .iter()
        .map(|r| r.expires.len())
        .max()
        .unwrap_or(0)
        .max(7);

    println!(
        "{:<8} {:<target_w$} {:<days_w$} {:<expires_w$} HINT",
        "STATUS", "TARGET", "DAYS LEFT", "EXPIRES"
    );
    for r in &rows {
        let label = format!("{:<8}", r.label);
        let label = if colorize {
            match r.severity {
                Severity::Ok => format!("\x1b[32m{label}\x1b[0m"),
                Severity::Warning => format!("\x1b[33m{label}\x1b[0m"),
                Severity::Critical => format!("\x1b[31m{label}\x1b[0m"),
            }
        } else {
            label
        };
        println!(
            "{label} {:<target_w$} {:<days_w$} {:<expires_w$} {}",
            r.target, r.days, r.expires, r.hint
        );
    }

    let worst = rows
        .iter()
        .map(|r| r.severity)
        .max()
        .unwrap_or(Severity::Ok);
    let critical = rows
        .iter()
        .filter(|r| r.severity == Severity::Critical)
        .count();
    let warning = rows
        .iter()
        .filter(|r| r.severity == Severity::Warning)
        .count();
    println!(
        "\n{} targets checked: {} critical, {} warning, {} ok",
        rows.len(),
        critical,
        warning,
        rows.len() - critical - warning,
    );

    match worst {
        Severity::Ok => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}

enum ScanState {
    Idle,
    Running(
        std::thread::JoinHandle<Vec<CertResult>>,
        std::sync::Arc<std::sync::atomic::AtomicU64>,
    ),
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    targets: Vec<Target>,
    timeout: Duration,
    interval: Option<u64>,
) -> std::io::Result<()> {
    let mut scan_state = ScanState::Idle;

    loop {
        // Pick up a finished background rescan, if any.
        if let ScanState::Running(handle, _) = &scan_state
            && handle.is_finished()
        {
            let ScanState::Running(handle, _) = std::mem::replace(&mut scan_state, ScanState::Idle)
            else {
                unreachable!()
            };
            app.set_results(handle.join().expect("scan thread panicked"));
        }

        let scan_progress = match &scan_state {
            ScanState::Running(_, progress) => Some(progress.load(Ordering::Relaxed)),
            ScanState::Idle => None,
        };
        terminal.draw(|frame| draw(frame, app, scan_progress, targets.len()))?;

        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            if app.show_detail.is_some() {
                // The popup is purely informational — any key dismisses it
                // back to the list, rather than also acting as a global
                // keybinding (so an accidental 'q' doesn't quit the whole
                // app while you're just reading a cert's details).
                app.show_detail = None;
                continue;
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Down => app.move_selection(true),
                KeyCode::Up => app.move_selection(false),
                KeyCode::Enter => app.show_detail = app.table_state.selected(),
                KeyCode::Char('r') if matches!(scan_state, ScanState::Idle) => {
                    let (handle, progress) = check_all_async(targets.clone(), timeout);
                    scan_state = ScanState::Running(handle, progress);
                }
                _ => {}
            }
        }

        if matches!(scan_state, ScanState::Idle)
            && let Some(secs) = interval
            && let Some(last) = app.last_scan
            && last.elapsed() >= Duration::from_secs(secs)
        {
            let (handle, progress) = check_all_async(targets.clone(), timeout);
            scan_state = ScanState::Running(handle, progress);
        }
    }
}

fn draw(frame: &mut Frame, app: &mut App, scan_progress: Option<u64>, total_targets: usize) {
    let layout = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(frame.area());

    let critical = app
        .results
        .iter()
        .filter(|r| app.row_color(r) == Color::Red)
        .count();
    let warn = app
        .results
        .iter()
        .filter(|r| app.row_color(r) == Color::Yellow)
        .count();
    let scan_note = match scan_progress {
        Some(n) => format!(" (rescanning {}/{}...)", n, total_targets),
        None => String::new(),
    };
    let header = format!(
        "certmonitor — {} targets, {} critical, {} warning{}   ↑/↓: select, Enter: details, r: rescan, q: quit",
        app.results.len(),
        critical,
        warn,
        scan_note,
    );
    frame.render_widget(Line::from(header), layout[0]);

    let rows: Vec<Row> = app
        .results
        .iter()
        .map(|r| {
            let color = app.row_color(r);
            let days_str = match r.status {
                Status::Ok(days) if days < 0 => format!("expired {}d ago", -days),
                Status::Ok(days) => format!("{}d", days),
                Status::Error(_) => "-".to_string(),
            };
            let target = format!("{}:{}", r.target.host, r.target.port);
            let expires = r.not_after.clone().unwrap_or_default();
            let issuer = r
                .issuer
                .clone()
                .or_else(|| match &r.status {
                    Status::Error(e) => Some(e.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            let hint = r.renewal_hint();

            Row::new(vec![
                Cell::from(days_str),
                Cell::from(target),
                Cell::from(expires),
                Cell::from(issuer),
                Cell::from(hint),
            ])
            .style(Style::default().fg(color))
        })
        .collect();

    let widths = [
        Constraint::Length(16),
        Constraint::Length(28),
        Constraint::Length(12),
        Constraint::Length(28),
        Constraint::Min(20),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "Days Left",
                "Host:Port",
                "Expires On",
                "Issuer",
                "Renewal hint",
            ])
            .style(Style::default().add_modifier(ratatui::style::Modifier::BOLD)),
        )
        .block(Block::bordered().title("Certificates, soonest expiry first"))
        .row_highlight_style(Style::default().reversed())
        .highlight_symbol("> ");
    frame.render_stateful_widget(table, layout[1], &mut app.table_state);

    let status = app
        .last_scan
        .map(|t| format!("Last scan: {:.0}s ago", t.elapsed().as_secs_f64()))
        .unwrap_or_default();
    frame.render_widget(Paragraph::new(status), layout[2]);

    if let Some(i) = app.show_detail
        && let Some(result) = app.results.get(i)
    {
        let color = app.row_color(result);
        draw_detail_popup(frame, result, color);
    }
}

fn draw_detail_popup(frame: &mut Frame, result: &CertResult, color: Color) {
    let area = centered_rect(70, 13, frame.area());
    frame.render_widget(ratatui::widgets::Clear, area);

    let days_line = match result.status {
        Status::Ok(days) if days < 0 => format!("Expired {} days ago", -days),
        Status::Ok(days) => format!("{} days left", days),
        Status::Error(_) => "Check failed".to_string(),
    };

    let mut lines = vec![
        format!("{}:{}", result.target.host, result.target.port),
        String::new(),
        days_line,
    ];
    match &result.status {
        Status::Error(e) => lines.push(format!("Error: {}", e)),
        Status::Ok(_) => {
            lines.push(format!(
                "Expires:  {}",
                result.not_after.as_deref().unwrap_or("-")
            ));
            lines.push(format!(
                "Subject:  {}",
                result.subject.as_deref().unwrap_or("-")
            ));
            lines.push(format!(
                "Issuer:   {}",
                result.issuer.as_deref().unwrap_or("-")
            ));
            lines.push(String::new());
            lines.push(format!("Hint: {}", result.renewal_hint()));
        }
    }
    lines.push(String::new());
    lines.push("any key: close".to_string());

    let popup = Paragraph::new(lines.join("\n"))
        .wrap(ratatui::widgets::Wrap { trim: false })
        .style(Style::default().fg(color))
        .block(Block::bordered().title("Certificate details"));
    frame.render_widget(popup, area);
}

/// A Rect `pct_x`% as wide as `area` and `rows` tall, centered within it.
fn centered_rect(pct_x: u16, rows: u16, area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let rows = rows.min(area.height);
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(rows),
        Constraint::Fill(1),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - pct_x) / 2),
        Constraint::Percentage(pct_x),
        Constraint::Percentage((100 - pct_x) / 2),
    ])
    .split(vertical[1])[1]
}
