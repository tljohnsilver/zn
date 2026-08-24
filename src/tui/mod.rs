use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    terminal::Terminal,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use reqwest::Client;
use serde::Deserialize;
use std::io;
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize)]
struct ApiLogEntry {
    timestamp: String,
    tool_name: String,
    status: String,
    event: String,
    anomaly_score: Option<f32>,
}

#[derive(Debug, Deserialize, Default)]
struct ApiStatsResponse {
    stats: ApiStats,
}

#[derive(Debug, Deserialize, Default)]
struct ApiStats {
    total: u64,
    allowed: u64,
    denied: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ApiPendingAction {
    pub id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub timestamp: String,
    pub required_m: u32,
    pub signatures: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ApiLogsResponse {
    entries: Vec<ApiLogEntry>,
}

#[derive(Debug, Deserialize)]
struct ApiConsensusResponse {
    entries: Vec<ApiPendingAction>,
}

pub struct TuiApp {
    client: Client,
    logs: Vec<ApiLogEntry>,
    pending_actions: Vec<ApiPendingAction>,
    stats: ApiStats,
    last_update: Instant,
    api_url: String,
    connection_status: String,
    connection_color: Color,
}

impl TuiApp {
    pub async fn run(api_key: Option<String>) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Resolve API Key (CLI > Env > Error)
        let resolved_key = match api_key {
            Some(key) => key,
            None => std::env::var("ZN_API_KEY").map_err(|_| {
                anyhow::anyhow!("No API key provided via CLI and ZN_API_KEY is not set.")
            })?,
        };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("X-API-Key", resolved_key.parse().unwrap());

        let mut app = TuiApp {
            client: Client::builder()
                .default_headers(headers)
                .timeout(Duration::from_secs(1))
                .build()?,
            logs: Vec::new(),
            pending_actions: Vec::new(),
            stats: ApiStats::default(),
            last_update: Instant::now(),
            api_url: "http://localhost:9090".to_string(),
            connection_status: "CONNECTING".to_string(),
            connection_color: Color::Yellow,
        };

        // Initial fetch
        app.fetch_data().await;

        loop {
            // Draw UI
            terminal.draw(|f| ui(f, &app))?;

            // Input handling
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.code == KeyCode::Char('q') {
                        break;
                    }
                }
            }

            // Periodic Update (1s)
            if app.last_update.elapsed() > Duration::from_secs(1) {
                app.fetch_data().await;
                app.last_update = Instant::now();
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
    }

    async fn fetch_data(&mut self) {
        // Fetch Stats
        match self
            .client
            .get(format!("{}/api/v1/stats", self.api_url))
            .send()
            .await
        {
            Ok(res) => {
                if let Ok(json) = res.json::<ApiStatsResponse>().await {
                    self.stats = json.stats;
                    self.connection_status = "CONNECTED".to_string();
                    self.connection_color = Color::Green;
                }
            }
            Err(_) => {
                self.connection_status = "DISCONNECTED".to_string();
                self.connection_color = Color::Red;
            }
        }

        // Fetch Logs if connected
        if self.connection_status == "CONNECTED" {
            // Logs
            if let Ok(res) = self
                .client
                .get(format!("{}/api/v1/logs", self.api_url))
                .send()
                .await
            {
                if let Ok(json) = res.json::<ApiLogsResponse>().await {
                    self.logs = json.entries;
                }
            }
            // Pending Consensus
            if let Ok(res) = self
                .client
                .get(format!("{}/api/v1/consensus/pending", self.api_url))
                .send()
                .await
            {
                if let Ok(json) = res.json::<ApiConsensusResponse>().await {
                    self.pending_actions = json.entries;
                }
            }
        }
    }
}

fn ui(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3), // Header
                Constraint::Length(6), // Stats
                Constraint::Min(0),    // Content (Logs + Governance)
                Constraint::Length(1), // Footer
            ]
            .as_ref(),
        )
        .split(size);

    // 1. PREMIUM HEADER
    let header_chunk = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(25)])
        .split(chunks[0]);

    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(100, 100, 255)))
        .title(" zn Control Plane 🛡️ ");

    let tagline = Paragraph::new(" Active Defense & Intent Governance ")
        .style(Style::default().fg(Color::Gray))
        .alignment(ratatui::layout::Alignment::Center);

    f.render_widget(tagline.block(header_block), header_chunk[0]);

    let status_para = Paragraph::new(format!(" ● {}", app.connection_status))
        .style(
            Style::default()
                .fg(app.connection_color)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(status_para, header_chunk[1]);

    // 2. STATS (Glow Design)
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(33),
            ]
            .as_ref(),
        )
        .split(chunks[1]);

    let total_block = Paragraph::new(format!("\n  {}", app.stats.total))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 🔍 INTERCEPTIONS "),
        )
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(total_block, stats_chunks[0]);

    let blocks_block = Paragraph::new(format!("\n  {}", app.stats.denied))
        .block(Block::default().borders(Borders::ALL).title(" ⛔ BLOCKED "))
        .style(
            Style::default()
                .fg(Color::Rgb(255, 100, 100))
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(blocks_block, stats_chunks[1]);

    let allowed_block = Paragraph::new(format!("\n  {}", app.stats.allowed))
        .block(Block::default().borders(Borders::ALL).title(" ✅ ALLOWED "))
        .style(
            Style::default()
                .fg(Color::Rgb(100, 255, 100))
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(allowed_block, stats_chunks[2]);

    // 3. MAIN CONTENT (Logs + Governance Side-by-Side)
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(65), // Audit Stream
                Constraint::Percentage(35), // Governance Queue
            ]
            .as_ref(),
        )
        .split(chunks[2]);

    // Logs List (Clean)
    let log_items: Vec<ListItem> = app
        .logs
        .iter()
        .take(50)
        .map(|log| {
            let (icon, color) = if log.status == "DENIED" {
                (" ✖ ", Color::Rgb(255, 120, 120))
            } else {
                (" ✔ ", Color::Rgb(120, 255, 120))
            };

            let neural_tag = match log.anomaly_score {
                Some(score) if score > 1.2 => " 🔥 RISKY".to_string(),
                Some(_) => " ✨ SAFE".to_string(),
                None => "".to_string(),
            };

            let time = log
                .timestamp
                .split('T')
                .nth(1)
                .unwrap_or("")
                .split(':')
                .take(2)
                .collect::<Vec<_>>()
                .join(":");
            let content = format!(
                "{} {} | {:<15} | {}{}",
                icon, time, log.tool_name, log.event, neural_tag
            );
            ListItem::new(content).style(Style::default().fg(color))
        })
        .collect();

    let logs_list = List::new(log_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" 📡 LIVE AUDIT STREAM ")
            .title_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(logs_list, content_chunks[0]);

    // Governance Queue (M-of-N)
    let gov_items: Vec<ListItem> = app
        .pending_actions
        .iter()
        .map(|action| {
            let content = format!(
                " ⏳ {} ({} Sigs Required)\n    Agent: {}",
                action.tool_name, action.required_m, action.agent_id
            );
            ListItem::new(content).style(Style::default().fg(Color::Rgb(255, 180, 100)))
        })
        .collect();

    let gov_list = List::new(gov_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" ⚖️ M-of-N GOVERNANCE ")
            .title_style(Style::default().fg(Color::Magenta)),
    );
    f.render_widget(gov_list, content_chunks[1]);

    // 4. FOOTER
    let footer_text = format!(
        " Press 'q' to exit | API: {} | Active Shields: SQL, LFI, Loop, Caching ",
        app.api_url
    );
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::DarkGray))
        .alignment(ratatui::layout::Alignment::Left);
    f.render_widget(footer, chunks[3]);
}
