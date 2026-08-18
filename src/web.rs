use crate::scan::{CertResult, Severity, Status, Target, check_all, severity};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tiny_http::{Header, Response, Server};

struct SharedState {
    results: Vec<CertResult>,
    last_scan: Option<Instant>,
}

/// Serve an auto-refreshing HTML page at `addr` showing the same ranked
/// table as the TUI. A background thread rescans every `interval` seconds
/// and the HTTP handler just renders whatever the latest scan left behind —
/// requests never block on a live scan.
pub fn serve(
    addr: &str,
    targets: Vec<Target>,
    timeout: Duration,
    warn_days: i64,
    critical_days: i64,
    interval: u64,
) -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(SharedState {
        results: Vec::new(),
        last_scan: None,
    }));

    {
        let state = Arc::clone(&state);
        let targets = targets.clone();
        std::thread::spawn(move || {
            loop {
                let results = check_all(&targets, timeout);
                let mut guard = state.lock().unwrap();
                guard.results = results;
                guard.last_scan = Some(Instant::now());
                drop(guard);
                std::thread::sleep(Duration::from_secs(interval));
            }
        });
    }

    let server = Server::http(addr).map_err(std::io::Error::other)?;
    eprintln!("Serving on http://{addr}/  (rescanning every {interval}s)");

    for request in server.incoming_requests() {
        let body = {
            let guard = state.lock().unwrap();
            render_page(
                &guard.results,
                &guard.last_scan,
                warn_days,
                critical_days,
                interval,
            )
        };
        let header = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
            .expect("static header is valid");
        let response = Response::from_string(body).with_header(header);
        let _ = request.respond(response);
    }

    Ok(())
}

fn render_page(
    results: &[CertResult],
    last_scan: &Option<Instant>,
    warn_days: i64,
    critical_days: i64,
    interval: u64,
) -> String {
    let scanned_note = match last_scan {
        Some(t) => format!("last scan {:.0}s ago", t.elapsed().as_secs_f64()),
        None => "scanning...".to_string(),
    };

    let mut rows = String::new();
    for r in results {
        let sev = severity(r, warn_days, critical_days);
        let color = match sev {
            Severity::Ok => "#1a7f37",
            Severity::Warning => "#9a6700",
            Severity::Critical => "#cf222e",
        };
        let label = match sev {
            Severity::Ok => "OK",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
        };
        let days = match r.status {
            Status::Ok(days) if days < 0 => format!("expired {}d ago", -days),
            Status::Ok(days) => format!("{days}d"),
            Status::Error(_) => "-".to_string(),
        };
        let expires = r.not_after.as_deref().unwrap_or("-");
        let hint = match &r.status {
            Status::Error(e) => e.clone(),
            Status::Ok(_) => r.renewal_hint().to_string(),
        };
        rows.push_str(&format!(
            "<tr style=\"color:{color}\"><td>{label}</td><td>{}</td><td>{days}</td><td>{expires}</td><td>{hint}</td></tr>\n",
            html_escape(&format!("{}:{}", r.target.host, r.target.port)),
        ));
    }

    let critical = results
        .iter()
        .filter(|r| severity(r, warn_days, critical_days) == Severity::Critical)
        .count();
    let warning = results
        .iter()
        .filter(|r| severity(r, warn_days, critical_days) == Severity::Warning)
        .count();

    format!(
        r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="{interval}">
<title>certmonitor</title>
<style>
  body {{ font-family: monospace; background: #0d1117; color: #e6edf3; padding: 1.5rem; }}
  h1 {{ font-size: 1.1rem; font-weight: normal; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 0.3rem 0.8rem; border-bottom: 1px solid #30363d; }}
  th {{ color: #8b949e; font-weight: normal; }}
</style>
</head>
<body>
<h1>certmonitor — {} targets, {critical} critical, {warning} warning ({scanned_note})</h1>
<table>
<tr><th>Status</th><th>Target</th><th>Days Left</th><th>Expires</th><th>Hint</th></tr>
{rows}</table>
</body>
</html>
"#,
        results.len(),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
