//! Native egui GUI — the default frontend. Three-pane Lancer-standard layout
//! (inputs | results | detail) over the same [`crate::pipeline`] the CLI uses.

use std::path::PathBuf;

use ar_core::{
    ComplianceMode, Config, Framework, HardenOptions, ParseOptions, Report, ReportFormat,
    Severity, TestOptions,
};
use crossbeam_channel::{unbounded, Receiver, Sender};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use egui_plot::{Bar, BarChart, Plot};

use crate::pipeline::{run_scan, ScanRequest};
use crate::server::{self, Shared};

/// Launch the GUI (blocks until the window closes).
pub fn launch() -> anyhow::Result<()> {
    let shared = server::new_shared();
    let port = server::start(shared.clone());

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 840.0])
            .with_min_inner_size([900.0, 560.0])
            .with_title("lancer-agentic-radar"),
        ..Default::default()
    };

    let result = eframe::run_native(
        "lancer-agentic-radar",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Box::new(App::new(shared, port)) as Box<dyn eframe::App>
        }),
    );

    server::cleanup_port_file();
    result.map_err(|e| anyhow::anyhow!("GUI error: {e}"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Findings,
    Graph,
    Compliance,
}

enum WorkerCmd {
    Scan(u64, Box<ScanRequest>),
}

enum WorkerMsg {
    Progress(u64, String),
    Done(u64, Box<Report>),
    Error(u64, String),
}

struct Worker {
    tx: Sender<WorkerCmd>,
    rx: Receiver<WorkerMsg>,
}

impl Worker {
    fn new() -> Self {
        let (tx_cmd, rx_cmd) = unbounded::<WorkerCmd>();
        let (tx_msg, rx_msg) = unbounded::<WorkerMsg>();
        std::thread::spawn(move || {
            while let Ok(cmd) = rx_cmd.recv() {
                match cmd {
                    WorkerCmd::Scan(gen, req) => {
                        let _ = tx_msg.send(WorkerMsg::Progress(gen, "scanning…".into()));
                        match run_scan(&req) {
                            Ok(r) => {
                                let _ = tx_msg.send(WorkerMsg::Done(gen, Box::new(r)));
                            }
                            Err(e) => {
                                let _ = tx_msg.send(WorkerMsg::Error(gen, e.to_string()));
                            }
                        }
                    }
                }
            }
        });
        Worker {
            tx: tx_cmd,
            rx: rx_msg,
        }
    }

    fn scan(&self, gen: u64, req: ScanRequest) {
        let _ = self.tx.send(WorkerCmd::Scan(gen, Box::new(req)));
    }
}

struct App {
    shared: Shared,
    port: u16,
    worker: Worker,

    // inputs
    input_path: String,
    framework: Option<Framework>,
    dynamic: bool,
    harden: bool,
    mcp_only: bool,
    endpoint: String,
    compliance: Vec<(ComplianceMode, bool)>,
    export_format: ReportFormat,

    // results
    report: Option<Report>,
    selected: Option<usize>,
    view: View,

    // status
    status: String,
    busy: bool,
    generation: u64,
    toast: Option<String>,
}

impl App {
    fn new(shared: Shared, port: u16) -> Self {
        App {
            shared,
            port,
            worker: Worker::new(),
            input_path: ".".to_string(),
            framework: None,
            dynamic: false,
            harden: false,
            mcp_only: false,
            endpoint: String::new(),
            compliance: ComplianceMode::ALL.iter().map(|m| (*m, false)).collect(),
            export_format: ReportFormat::Json,
            report: None,
            selected: None,
            view: View::Findings,
            status: format!("idle — integration port {port}"),
            busy: false,
            generation: 0,
            toast: None,
        }
    }

    fn start_scan(&mut self) {
        self.generation += 1;
        self.busy = true;
        self.status = "scanning…".into();
        self.selected = None;

        let mut config = Config::default();
        config.compliance_modes = self
            .compliance
            .iter()
            .filter(|(_, on)| *on)
            .map(|(m, _)| *m)
            .collect();

        let mut test_opts = TestOptions::default();
        if !self.endpoint.trim().is_empty() {
            test_opts.endpoint = Some(self.endpoint.trim().to_string());
        }

        let parse_opts = ParseOptions {
            framework: self.framework,
            mcp_only: self.mcp_only,
            trust: config.trust.clone(),
            ..ParseOptions::default()
        };

        let req = ScanRequest {
            input: PathBuf::from(self.input_path.trim()),
            framework: self.framework,
            config,
            parse_opts,
            dynamic: self.dynamic,
            harden: self.harden,
            test_opts,
            harden_opts: HardenOptions::default(),
        };

        if let Ok(mut s) = self.shared.lock() {
            s.busy = true;
            s.status = "scanning".into();
            s.last_input = Some(req.input.clone());
        }
        self.worker.scan(self.generation, req);
    }

    fn poll_worker(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.worker.rx.try_recv() {
            match msg {
                WorkerMsg::Progress(gen, s) if gen == self.generation => {
                    self.status = s;
                }
                WorkerMsg::Done(gen, report) if gen == self.generation => {
                    let report = *report;
                    let n = report.active_findings().count();
                    self.status = format!(
                        "done — {} agent(s), {} tool(s), {} finding(s)",
                        report.stats.agents, report.stats.tools, n
                    );
                    if let Ok(mut s) = self.shared.lock() {
                        s.report = Some(report.clone());
                        s.busy = false;
                        s.status = "done".into();
                    }
                    self.report = Some(report);
                    self.busy = false;
                }
                WorkerMsg::Error(gen, e) if gen == self.generation => {
                    self.status = format!("error: {e}");
                    self.busy = false;
                    if let Ok(mut s) = self.shared.lock() {
                        s.busy = false;
                        s.status = "error".into();
                    }
                }
                // stale (cancelled) messages — ignore.
                _ => {}
            }
        }
        if self.busy {
            ctx.request_repaint();
        }
    }

    fn poll_import(&mut self) {
        let imported = self
            .shared
            .lock()
            .ok()
            .and_then(|mut s| s.pending_import.take());
        if let Some(path) = imported {
            self.input_path = path;
            self.toast = Some("Received target from a sibling Lancer tool".into());
        }
    }

    fn export_report(&mut self) {
        let Some(report) = &self.report else {
            self.toast = Some("Nothing to export — run a scan first".into());
            return;
        };
        let fmt = self.export_format;
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("agentic-radar-report.{}", fmt.extension()))
            .save_file()
        {
            let rendered = ar_report::render(report, fmt);
            match std::fs::write(&path, rendered) {
                Ok(_) => self.toast = Some(format!("Exported {} report", fmt.id())),
                Err(e) => self.toast = Some(format!("Export failed: {e}")),
            }
        }
    }

    fn copy_to_clipboard(text: &str) -> bool {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            cb.set_text(text.to_string()).is_ok()
        } else {
            false
        }
    }
}

struct RowData {
    idx: usize,
    severity: Severity,
    detector: String,
    title: String,
    confirmed: bool,
}

struct DetailData {
    title: String,
    detector: String,
    severity: Severity,
    category: String,
    confirmed: bool,
    description: String,
    evidence: Option<String>,
    fix: Option<String>,
    patch: Option<String>,
    agent: Option<String>,
    tool: Option<String>,
    location: String,
    compliance: Vec<String>,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker(ctx);
        self.poll_import();

        // ---- precompute view data from the report (avoid borrow conflicts) --
        let rows: Vec<RowData> = self
            .report
            .as_ref()
            .map(|r| {
                r.active_findings()
                    .enumerate()
                    .map(|(i, f)| RowData {
                        idx: i,
                        severity: f.severity,
                        detector: f.detector_id.clone(),
                        title: f.title.clone(),
                        confirmed: f.dynamically_confirmed,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let detail: Option<DetailData> = self.selected.and_then(|i| {
            self.report
                .as_ref()
                .and_then(|r| r.active_findings().nth(i))
                .map(detail_from)
        });

        let mermaid = if self.view == View::Graph {
            self.report.as_ref().map(|r| ar_report::mermaid(&r.graph))
        } else {
            None
        };

        let sev_counts = self
            .report
            .as_ref()
            .map(|r| r.severity_counts())
            .unwrap_or_default();

        let compliance_summary = self.report.as_ref().map(|r| r.compliance_summary.clone());

        // ---- menu bar -------------------------------------------------------
        let mut do_scan = false;
        let mut do_export = false;
        let mut do_browse = false;
        let mut clicked_row: Option<usize> = None;
        let mut copy_text: Option<String> = None;

        egui::TopBottomPanel::top("menubar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open folder…").clicked() {
                        do_browse = true;
                        ui.close_menu();
                    }
                    if ui.button("Export report…").clicked() {
                        do_export = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("Run scan").clicked() {
                        do_scan = true;
                        ui.close_menu();
                    }
                });
                ui.menu_button("Help", |ui| {
                    ui.label("lancer-agentic-radar");
                    ui.label(format!("v{}", env!("CARGO_PKG_VERSION")));
                    ui.label("Security scanner for agentic AI workflows.");
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("⇄ :{}", self.port));
                });
            });
        });

        // ---- left: inputs ---------------------------------------------------
        egui::SidePanel::left("inputs")
            .resizable(true)
            .default_width(290.0)
            .width_range(220.0..=420.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.heading("Target");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.input_path);
                    if ui.button("…").clicked() {
                        do_browse = true;
                    }
                });

                ui.add_space(8.0);
                ui.label("Framework");
                egui::ComboBox::from_id_source("framework")
                    .selected_text(
                        self.framework
                            .map(|f| f.display_name())
                            .unwrap_or("auto-detect"),
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.framework, None, "auto-detect");
                        for f in Framework::ALL {
                            ui.selectable_value(&mut self.framework, Some(f), f.display_name());
                        }
                    });

                ui.add_space(8.0);
                ui.checkbox(&mut self.mcp_only, "MCP only");
                ui.checkbox(&mut self.dynamic, "Dynamic probe");
                ui.checkbox(&mut self.harden, "Harden prompts");
                if self.dynamic {
                    ui.label("Endpoint URL");
                    ui.text_edit_singleline(&mut self.endpoint);
                }

                ui.add_space(8.0);
                ui.collapsing("Compliance mappings", |ui| {
                    for (mode, on) in self.compliance.iter_mut() {
                        ui.checkbox(on, mode.title());
                    }
                });

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("▶ Scan"))
                        .clicked()
                    {
                        do_scan = true;
                    }
                    if ui
                        .add_enabled(self.busy, egui::Button::new("■ Stop"))
                        .clicked()
                    {
                        // Bump generation so any in-flight result is discarded.
                        self.generation += 1;
                        self.busy = false;
                        self.status = "cancelled".into();
                    }
                });

                if self.busy {
                    ui.add_space(6.0);
                    ui.add(egui::Spinner::new());
                }
            });

        // ---- right: detail --------------------------------------------------
        egui::SidePanel::right("detail")
            .resizable(true)
            .default_width(380.0)
            .width_range(280.0..=560.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.heading("Detail");
                ui.separator();
                match &detail {
                    None => {
                        ui.label("Select a finding to see details.");
                    }
                    Some(d) => {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.colored_label(sev_color(d.severity), d.severity.as_str());
                                ui.strong(&d.title);
                            });
                            ui.label(format!("detector: {}", d.detector));
                            ui.label(format!("category: {}", d.category));
                            if d.confirmed {
                                ui.colored_label(egui::Color32::LIGHT_RED, "dynamically confirmed");
                            }
                            if let Some(a) = &d.agent {
                                ui.label(format!("agent: {a}"));
                            }
                            if let Some(t) = &d.tool {
                                ui.label(format!("tool: {t}"));
                            }
                            if !d.location.is_empty() {
                                ui.label(format!("location: {}", d.location));
                            }
                            ui.separator();
                            ui.label(&d.description);
                            if let Some(ev) = &d.evidence {
                                ui.collapsing("Evidence", |ui| {
                                    ui.monospace(ev);
                                });
                            }
                            if let Some(fix) = &d.fix {
                                ui.collapsing("Fix", |ui| {
                                    ui.label(fix);
                                });
                            }
                            if let Some(patch) = &d.patch {
                                ui.collapsing("Hardened rewrite", |ui| {
                                    ui.monospace(patch);
                                    if ui.button("Copy").clicked() {
                                        copy_text = Some(patch.clone());
                                    }
                                });
                            }
                            if !d.compliance.is_empty() {
                                ui.separator();
                                ui.label("Compliance:");
                                for c in &d.compliance {
                                    ui.label(format!("• {c}"));
                                }
                            }
                        });
                    }
                }
            });

        // ---- bottom: status -------------------------------------------------
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Export").clicked() {
                        do_export = true;
                    }
                    egui::ComboBox::from_id_source("export_fmt")
                        .selected_text(self.export_format.id())
                        .show_ui(ui, |ui| {
                            for f in ReportFormat::ALL {
                                ui.selectable_value(&mut self.export_format, f, f.id());
                            }
                        });
                    if ui.add_enabled(!self.busy, egui::Button::new("Run")).clicked() {
                        do_scan = true;
                    }
                    if ui.button("Open").clicked() {
                        do_browse = true;
                    }
                });
            });
        });

        // ---- center: results ------------------------------------------------
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.view, View::Findings, "Findings");
                ui.selectable_value(&mut self.view, View::Graph, "Graph");
                ui.selectable_value(&mut self.view, View::Compliance, "Compliance");
                ui.separator();
                ui.label(format!("{} finding(s)", rows.len()));
            });
            ui.separator();

            match self.view {
                View::Findings => {
                    if !sev_counts.is_empty() {
                        severity_chart(ui, &sev_counts);
                        ui.separator();
                    }
                    if rows.is_empty() {
                        ui.label("No findings. Run a scan on the left.");
                    } else {
                        TableBuilder::new(ui)
                            .striped(true)
                            .resizable(true)
                            .column(Column::auto().at_least(70.0))
                            .column(Column::initial(220.0).at_least(120.0))
                            .column(Column::remainder())
                            .header(20.0, |mut header| {
                                header.col(|ui| {
                                    ui.strong("Severity");
                                });
                                header.col(|ui| {
                                    ui.strong("Detector");
                                });
                                header.col(|ui| {
                                    ui.strong("Title");
                                });
                            })
                            .body(|mut body| {
                                for row in &rows {
                                    body.row(20.0, |mut tr| {
                                        tr.col(|ui| {
                                            ui.colored_label(
                                                sev_color(row.severity),
                                                row.severity.as_str(),
                                            );
                                        });
                                        tr.col(|ui| {
                                            ui.label(&row.detector);
                                        });
                                        tr.col(|ui| {
                                            let label = if row.confirmed {
                                                format!("✔ {}", row.title)
                                            } else {
                                                row.title.clone()
                                            };
                                            if ui
                                                .selectable_label(
                                                    self.selected == Some(row.idx),
                                                    label,
                                                )
                                                .clicked()
                                            {
                                                clicked_row = Some(row.idx);
                                            }
                                        });
                                    });
                                }
                            });
                    }
                }
                View::Graph => {
                    ui.horizontal(|ui| {
                        ui.label("Mermaid graph source (paste into mermaid.live):");
                        if ui.button("Copy").clicked() {
                            if let Some(m) = &mermaid {
                                copy_text = Some(m.clone());
                            }
                        }
                    });
                    egui::ScrollArea::both().show(ui, |ui| {
                        let text = mermaid.clone().unwrap_or_else(|| "// run a scan".into());
                        ui.monospace(text);
                    });
                }
                View::Compliance => {
                    egui::ScrollArea::vertical().show(ui, |ui| match &compliance_summary {
                        None => {
                            ui.label("Run a scan to see compliance coverage.");
                        }
                        Some(cs) => {
                            ui.heading("OWASP Agentic 2026 coverage");
                            for (code, n) in &cs.owasp_agentic_2026 {
                                ui.label(format!("{code}: {n}"));
                            }
                            if !cs.owasp_llm_2025.is_empty() {
                                ui.separator();
                                ui.heading("OWASP LLM 2025");
                                for (code, n) in &cs.owasp_llm_2025 {
                                    ui.label(format!("{code}: {n}"));
                                }
                            }
                            if !cs.mitre_atlas.is_empty() {
                                ui.separator();
                                ui.heading("MITRE ATLAS");
                                for (code, n) in &cs.mitre_atlas {
                                    ui.label(format!("{code}: {n}"));
                                }
                            }
                        }
                    });
                }
            }
        });

        // ---- toast ----------------------------------------------------------
        if let Some(msg) = self.toast.clone() {
            egui::Area::new(egui::Id::new("toast"))
                .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -48.0))
                .show(ctx, |ui| {
                    egui::Frame::popup(ui.style()).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(&msg);
                            if ui.button("✕").clicked() {
                                self.toast = None;
                            }
                        });
                    });
                });
        }

        // ---- apply deferred actions ----------------------------------------
        if let Some(i) = clicked_row {
            self.selected = Some(i);
        }
        if let Some(t) = copy_text {
            if Self::copy_to_clipboard(&t) {
                self.toast = Some("Copied to clipboard".into());
            }
        }
        if do_browse {
            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                self.input_path = dir.display().to_string();
            }
        }
        if do_export {
            self.export_report();
        }
        if do_scan && !self.busy {
            self.start_scan();
        }
    }
}

fn detail_from(f: &ar_core::Finding) -> DetailData {
    let mut compliance = Vec::new();
    for c in &f.compliance.owasp_agentic_2026 {
        compliance.push(format!("{}", c));
    }
    for c in &f.compliance.owasp_llm_2025 {
        compliance.push(format!("{}", c));
    }
    for a in &f.compliance.eu_ai_act {
        compliance.push(format!("{}", a));
    }
    for n in &f.compliance.nist_ai_rmf {
        compliance.push(format!("NIST {n}"));
    }
    for m in &f.compliance.mitre_atlas {
        compliance.push(format!("ATLAS {m}"));
    }
    if let Some(v) = &f.compliance.aivss {
        compliance.push(v.vector_string());
    }
    DetailData {
        title: f.title.clone(),
        detector: f.detector_id.clone(),
        severity: f.severity,
        category: f.category.title().to_string(),
        confirmed: f.dynamically_confirmed,
        description: f.description.clone(),
        evidence: f.evidence.clone(),
        fix: f.fix_suggestion.clone(),
        patch: f.remediation_patch.clone(),
        agent: f.agent.as_ref().map(|a| a.as_str().to_string()),
        tool: f.tool.as_ref().map(|t| t.as_str().to_string()),
        location: f.location.display_path(),
        compliance,
    }
}

fn sev_color(s: Severity) -> egui::Color32 {
    match s {
        Severity::Critical => egui::Color32::from_rgb(185, 28, 28),
        Severity::High => egui::Color32::from_rgb(234, 88, 12),
        Severity::Medium => egui::Color32::from_rgb(202, 138, 4),
        Severity::Low => egui::Color32::from_rgb(37, 99, 235),
        Severity::Info => egui::Color32::from_rgb(148, 163, 184),
    }
}

fn severity_chart(ui: &mut egui::Ui, counts: &std::collections::BTreeMap<Severity, usize>) {
    let bars: Vec<Bar> = Severity::ALL
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let v = *counts.get(s).unwrap_or(&0) as f64;
            Bar::new(i as f64, v).name(s.as_str())
        })
        .collect();
    let chart = BarChart::new(bars).color(egui::Color32::from_rgb(120, 144, 200));
    Plot::new("severity_chart")
        .height(120.0)
        .show_axes([false, true])
        .show(ui, |plot_ui| {
            plot_ui.bar_chart(chart);
        });
}
