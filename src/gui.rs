use anyhow::Result;
use eframe::egui;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};

use crate::codegen::sanitize_c_ident;
use crate::diff::{compute_diff_report, parse_dump_cs, ParsedClass};
use crate::package::is_package_path;
use crate::profile::DumpProfile;
use crate::{
    execute_dump, execute_dump_package, execute_inspect, execute_inspect_package, parse_hex_u64,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuiTheme {
    Emerald,
    Violet,
}

impl GuiTheme {
    fn accent(self) -> egui::Color32 {
        match self {
            GuiTheme::Emerald => egui::Color32::from_rgb(46, 213, 115),
            GuiTheme::Violet => egui::Color32::from_rgb(179, 136, 255),
        }
    }

    fn base(self) -> egui::Color32 {
        match self {
            GuiTheme::Emerald => egui::Color32::from_rgb(10, 15, 13),
            GuiTheme::Violet => egui::Color32::from_rgb(12, 9, 20),
        }
    }

    fn surface(self) -> egui::Color32 {
        match self {
            GuiTheme::Emerald => egui::Color32::from_rgb(18, 28, 24),
            GuiTheme::Violet => egui::Color32::from_rgb(22, 17, 36),
        }
    }

    fn panel_border(self) -> egui::Color32 {
        match self {
            GuiTheme::Emerald => egui::Color32::from_rgb(34, 62, 50),
            GuiTheme::Violet => egui::Color32::from_rgb(56, 40, 88),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    DumpInspect,
    Explorer,
    Diff,
    Profile,
}

enum WorkerMsg {
    Progress(f32, String),
    InspectDone(Result<String, String>),
    DumpDone(Result<(String, Vec<ParsedClass>), String>),
    ExplorerLoaded(Result<Vec<ParsedClass>, String>),
    DiffDone(Result<(String, usize, usize, usize), String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderModeChoice {
    Auto,
    Standard,
    Adaptive,
}

struct DumperApp {
    theme: GuiTheme,
    tab: ActiveTab,

    // Dump & Inspect state
    package_path: String,
    preferred_arch: String,
    binary_path: String,
    metadata_path: String,
    out_dir: String,
    profile_path: String,
    meta_reg_hex: String,
    code_reg_hex: String,
    dump_base_hex: String,
    memory_dump_mode: bool,
    log_text: String,

    // Worker communication
    tx: Sender<WorkerMsg>,
    rx: Receiver<WorkerMsg>,
    is_busy: bool,
    progress: f32,
    status_text: String,

    // Class & Offset Explorer state
    explorer_classes: Vec<ParsedClass>,
    explorer_search: String,
    filtered_indices: Vec<usize>,
    selected_filtered_pos: Option<usize>,
    explorer_source: String,

    // Diff state
    diff_old_path: String,
    diff_new_path: String,
    diff_filter: String,
    diff_only_changed: bool,
    diff_emit_cpp: bool,
    diff_output: String,
    diff_summary: String,

    // Profile Builder state
    prof_name: String,
    prof_header_offset: String,
    prof_xor_key: String,
    prof_expected_magic: String,
    prof_override_version: String,
    prof_header_mode: HeaderModeChoice,
    prof_register_symbol: String,
}

impl DumperApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        let app = Self {
            theme: GuiTheme::Emerald,
            tab: ActiveTab::DumpInspect,
            package_path: String::new(),
            preferred_arch: "auto".to_string(),
            binary_path: String::new(),
            metadata_path: String::new(),
            out_dir: "dump_out".to_string(),
            profile_path: String::new(),
            meta_reg_hex: String::new(),
            code_reg_hex: String::new(),
            dump_base_hex: String::new(),
            memory_dump_mode: false,
            log_text: "Ready. Select Binary + Metadata (or drop files anywhere onto the window).\n"
                .to_string(),
            tx,
            rx,
            is_busy: false,
            progress: 0.0,
            status_text: "Idle".to_string(),
            explorer_classes: Vec::new(),
            explorer_search: String::new(),
            filtered_indices: Vec::new(),
            selected_filtered_pos: None,
            explorer_source: "None loaded".to_string(),
            diff_old_path: String::new(),
            diff_new_path: String::new(),
            diff_filter: String::new(),
            diff_only_changed: true,
            diff_emit_cpp: false,
            diff_output: String::new(),
            diff_summary: String::new(),
            prof_name: "custom-game".to_string(),
            prof_header_offset: "0".to_string(),
            prof_xor_key: String::new(),
            prof_expected_magic: String::new(),
            prof_override_version: String::new(),
            prof_header_mode: HeaderModeChoice::Auto,
            prof_register_symbol: "il2cpp_codegen_register".to_string(),
        };
        apply_theme_visuals(&cc.egui_ctx, app.theme);
        app
    }

    fn rebuild_explorer_filter(&mut self) {
        let q = self.explorer_search.trim().to_lowercase();
        self.filtered_indices.clear();
        for (i, cls) in self.explorer_classes.iter().enumerate() {
            if q.is_empty()
                || cls.name.to_lowercase().contains(&q)
                || cls.namespace.to_lowercase().contains(&q)
                || cls.fields.iter().any(|f| f.name.to_lowercase().contains(&q))
                || cls.methods.iter().any(|m| m.name.to_lowercase().contains(&q))
            {
                self.filtered_indices.push(i);
            }
        }
        self.selected_filtered_pos = if self.filtered_indices.is_empty() {
            None
        } else {
            Some(0)
        };
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        for df in dropped {
            let Some(path) = df.path else {
                continue;
            };
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let path_s = path.to_string_lossy().into_owned();
            match ext.as_str() {
                "apk" | "xapk" | "apks" | "ipa" => {
                    self.package_path = path_s;
                    self.status_text = format!("Loaded package: {}", path.display());
                }
                "dat" => {
                    self.metadata_path = path_s;
                    self.status_text = format!("Loaded metadata: {}", path.display());
                }
                "so" | "dll" | "dylib" | "nso" | "wasm" => {
                    self.binary_path = path_s;
                    self.status_text = format!("Loaded binary: {}", path.display());
                }
                "json" => {
                    self.profile_path = path_s;
                    self.status_text = format!("Loaded profile: {}", path.display());
                }
                "cs" => {
                    if self.tab == ActiveTab::Diff {
                        if self.diff_old_path.is_empty() {
                            self.diff_old_path = path_s;
                        } else {
                            self.diff_new_path = path_s;
                        }
                    } else {
                        self.start_load_explorer_file(ctx, path);
                    }
                }
                _ => {
                    if path.is_dir() {
                        self.out_dir = path_s;
                    }
                }
            }
        }
    }

    fn poll_worker(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                WorkerMsg::Progress(p, line) => {
                    self.progress = p;
                    self.status_text = line.clone();
                    let _ = writeln!(self.log_text, "{}", line);
                }
                WorkerMsg::InspectDone(res) => {
                    self.is_busy = false;
                    self.progress = 1.0;
                    match res {
                        Ok(report) => {
                            self.log_text = report;
                            self.status_text = "Inspect completed".to_string();
                        }
                        Err(e) => {
                            let _ = writeln!(self.log_text, "\n[ERROR] {}", e);
                            self.status_text = format!("Inspect failed: {}", e);
                        }
                    }
                }
                WorkerMsg::DumpDone(res) => {
                    self.is_busy = false;
                    self.progress = 1.0;
                    match res {
                        Ok((log, classes)) => {
                            self.log_text = log;
                            let count = classes.len();
                            self.explorer_classes = classes;
                            self.explorer_source = format!("Latest dump ({})", self.out_dir);
                            self.rebuild_explorer_filter();
                            self.status_text = format!("Dump complete ({} types indexed)", count);
                        }
                        Err(e) => {
                            let _ = writeln!(self.log_text, "\n[ERROR] {}", e);
                            self.status_text = format!("Dump failed: {}", e);
                        }
                    }
                }
                WorkerMsg::ExplorerLoaded(res) => {
                    self.is_busy = false;
                    self.progress = 1.0;
                    match res {
                        Ok(classes) => {
                            let count = classes.len();
                            self.explorer_classes = classes;
                            self.rebuild_explorer_filter();
                            self.status_text = format!("Explorer loaded {} classes", count);
                        }
                        Err(e) => {
                            self.status_text = format!("Failed to load dump.cs: {}", e);
                        }
                    }
                }
                WorkerMsg::DiffDone(res) => {
                    self.is_busy = false;
                    self.progress = 1.0;
                    match res {
                        Ok((report, shifted, added, removed)) => {
                            self.diff_output = if report.is_empty() {
                                "No differences matched your filter.".to_string()
                            } else {
                                report
                            };
                            self.diff_summary = format!(
                                "{} shifted, {} added, {} removed",
                                shifted, added, removed
                            );
                            self.status_text = format!("Diff done: {}", self.diff_summary);
                        }
                        Err(e) => {
                            self.diff_output = format!("[ERROR] {}", e);
                            self.status_text = format!("Diff failed: {}", e);
                        }
                    }
                }
            }
        }
    }

    fn start_inspect(&mut self, ctx: &egui::Context) {
        let pkg_trim = self.package_path.trim();
        if self.is_busy || (pkg_trim.is_empty() && self.metadata_path.trim().is_empty()) {
            return;
        }
        let image_base = if self.dump_base_hex.trim().is_empty() {
            None
        } else {
            match parse_hex_u64(&self.dump_base_hex) {
                Ok(v) => Some(v),
                Err(e) => {
                    self.status_text = e;
                    return;
                }
            }
        };
        self.is_busy = true;
        self.progress = 0.2;
        self.status_text = "Inspecting...".to_string();
        self.log_text.clear();

        let pkg = (!pkg_trim.is_empty()).then(|| PathBuf::from(pkg_trim));
        let arch = (!self.preferred_arch.is_empty() && self.preferred_arch != "auto")
            .then(|| self.preferred_arch.clone());
        let meta = PathBuf::from(self.metadata_path.trim());
        let bin = (!self.binary_path.trim().is_empty()).then(|| PathBuf::from(self.binary_path.trim()));
        let prof = (!self.profile_path.trim().is_empty()).then(|| PathBuf::from(self.profile_path.trim()));
        let tx = self.tx.clone();
        let ctx_c = ctx.clone();

        std::thread::spawn(move || {
            let res = if let Some(pkg_p) = pkg {
                execute_inspect_package(&pkg_p, arch.as_deref(), prof.as_deref(), image_base)
            } else {
                execute_inspect(&meta, bin.as_deref(), prof.as_deref(), image_base)
            }
            .map_err(|e| format!("{:#}", e));
            let _ = tx.send(WorkerMsg::InspectDone(res));
            ctx_c.request_repaint();
        });
    }

    fn start_dump(&mut self, ctx: &egui::Context) {
        let pkg_trim = self.package_path.trim();
        let has_pkg = !pkg_trim.is_empty();
        if self.is_busy
            || (!has_pkg
                && (self.binary_path.trim().is_empty() || self.metadata_path.trim().is_empty()))
        {
            return;
        }
        let meta_reg = if self.meta_reg_hex.trim().is_empty() {
            None
        } else {
            match parse_hex_u64(&self.meta_reg_hex) {
                Ok(v) => Some(v),
                Err(e) => {
                    self.status_text = e;
                    return;
                }
            }
        };
        let code_reg = if self.code_reg_hex.trim().is_empty() {
            None
        } else {
            match parse_hex_u64(&self.code_reg_hex) {
                Ok(v) => Some(v),
                Err(e) => {
                    self.status_text = e;
                    return;
                }
            }
        };
        let image_base = if self.dump_base_hex.trim().is_empty() {
            None
        } else {
            match parse_hex_u64(&self.dump_base_hex) {
                Ok(v) => Some(v),
                Err(e) => {
                    self.status_text = e;
                    return;
                }
            }
        };

        self.is_busy = true;
        self.progress = 0.05;
        self.status_text = "Starting dump...".to_string();
        self.log_text.clear();

        let pkg = has_pkg.then(|| PathBuf::from(pkg_trim));
        let arch = (!self.preferred_arch.is_empty() && self.preferred_arch != "auto")
            .then(|| self.preferred_arch.clone());
        let bin = PathBuf::from(self.binary_path.trim());
        let meta = PathBuf::from(self.metadata_path.trim());
        let out = PathBuf::from(if self.out_dir.trim().is_empty() {
            "dump_out"
        } else {
            self.out_dir.trim()
        });
        let prof = (!self.profile_path.trim().is_empty()).then(|| PathBuf::from(self.profile_path.trim()));
        let mem_mode = self.memory_dump_mode;
        let tx = self.tx.clone();
        let ctx_c = ctx.clone();

        std::thread::spawn(move || {
            let res = if let Some(pkg_p) = pkg {
                execute_dump_package(
                    &pkg_p,
                    arch.as_deref(),
                    &out,
                    prof.as_deref(),
                    meta_reg,
                    code_reg,
                    mem_mode,
                    image_base,
                    |p, msg| {
                        let _ = tx.send(WorkerMsg::Progress(p, msg.to_string()));
                        ctx_c.request_repaint();
                    },
                )
            } else {
                execute_dump(
                    &bin,
                    &meta,
                    &out,
                    prof.as_deref(),
                    meta_reg,
                    code_reg,
                    mem_mode,
                    image_base,
                    |p, msg| {
                        let _ = tx.send(WorkerMsg::Progress(p, msg.to_string()));
                        ctx_c.request_repaint();
                    },
                )
            };
            let final_msg = match res {
                Ok((log, dump_cs)) => {
                    let _ = tx.send(WorkerMsg::Progress(0.97, "Indexing classes for Explorer...".into()));
                    ctx_c.request_repaint();
                    let classes: Vec<ParsedClass> = parse_dump_cs(&dump_cs).into_values().collect();
                    Ok((log, classes))
                }
                Err(e) => Err(format!("{:#}", e)),
            };
            let _ = tx.send(WorkerMsg::DumpDone(final_msg));
            ctx_c.request_repaint();
        });
    }

    fn start_load_explorer_file(&mut self, ctx: &egui::Context, path: PathBuf) {
        if self.is_busy {
            return;
        }
        self.is_busy = true;
        self.progress = 0.25;
        self.explorer_source = path.to_string_lossy().into_owned();
        self.status_text = format!("Parsing {}...", path.display());
        let tx = self.tx.clone();
        let ctx_c = ctx.clone();

        std::thread::spawn(move || {
            let res = std::fs::read_to_string(&path)
                .map(|txt| parse_dump_cs(&txt).into_values().collect())
                .map_err(|e| e.to_string());
            let _ = tx.send(WorkerMsg::ExplorerLoaded(res));
            ctx_c.request_repaint();
        });
    }

    fn start_diff(&mut self, ctx: &egui::Context) {
        if self.is_busy
            || self.diff_old_path.trim().is_empty()
            || self.diff_new_path.trim().is_empty()
        {
            return;
        }
        self.is_busy = true;
        self.progress = 0.3;
        self.status_text = "Computing diff...".to_string();

        let old_p = PathBuf::from(self.diff_old_path.trim());
        let new_p = PathBuf::from(self.diff_new_path.trim());
        let filter = (!self.diff_filter.trim().is_empty()).then(|| self.diff_filter.trim().to_string());
        let cpp = self.diff_emit_cpp;
        let changed = self.diff_only_changed;
        let tx = self.tx.clone();
        let ctx_c = ctx.clone();

        std::thread::spawn(move || {
            let res = compute_diff_report(&old_p, &new_p, filter.as_deref(), cpp, changed)
                .map_err(|e| format!("{:#}", e));
            let _ = tx.send(WorkerMsg::DiffDone(res));
            ctx_c.request_repaint();
        });
    }

    fn render_top_bar(&mut self, ctx: &egui::Context) {
        let accent = self.theme.accent();
        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::NONE
                    .fill(self.theme.surface())
                    .inner_margin(egui::Margin::symmetric(14, 10))
                    .stroke(egui::Stroke::new(1.0_f32, self.theme.panel_border())),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("IL2CPP DUMPER // RS")
                            .strong()
                            .size(16.0)
                            .color(accent),
                    );
                    ui.separator();

                    for (tab, label) in [
                        (ActiveTab::DumpInspect, "Dump & Inspect"),
                        (ActiveTab::Explorer, "Class Explorer"),
                        (ActiveTab::Diff, "Diff Updater"),
                        (ActiveTab::Profile, "Profile Builder"),
                    ] {
                        let selected = self.tab == tab;
                        let btn = egui::Button::new(
                            egui::RichText::new(label)
                                .color(if selected { egui::Color32::BLACK } else { egui::Color32::LIGHT_GRAY })
                                .strong(),
                        )
                        .fill(if selected { accent } else { egui::Color32::TRANSPARENT });
                        if ui.add(btn).clicked() {
                            self.tab = tab;
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let next_theme = match self.theme {
                            GuiTheme::Emerald => ("Theme: Emerald", GuiTheme::Violet),
                            GuiTheme::Violet => ("Theme: Violet", GuiTheme::Emerald),
                        };
                        if ui.button(next_theme.0).clicked() {
                            self.theme = next_theme.1;
                            apply_theme_visuals(ctx, self.theme);
                        }
                    });
                });
            });
    }

    fn render_status_bar(&self, ctx: &egui::Context) {
        let accent = self.theme.accent();
        egui::TopBottomPanel::bottom("status_bar")
            .frame(
                egui::Frame::NONE
                    .fill(self.theme.surface())
                    .inner_margin(egui::Margin::symmetric(14, 6))
                    .stroke(egui::Stroke::new(1.0_f32, self.theme.panel_border())),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&self.status_text).color(egui::Color32::LIGHT_GRAY));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.is_busy {
                            ui.add(
                                egui::ProgressBar::new(self.progress.clamp(0.0, 1.0))
                                    .desired_width(220.0)
                                    .fill(accent)
                                    .animate(true)
                                    .show_percentage(),
                            );
                        }
                    });
                });
            });
    }

    fn render_dump_inspect_tab(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let accent = self.theme.accent();
        egui::Frame::NONE
            .fill(self.theme.surface())
            .stroke(egui::Stroke::new(1.0_f32, self.theme.panel_border()))
            .corner_radius(6.0)
            .inner_margin(12.0)
            .show(ui, |ui| {
                egui::Grid::new("paths_grid")
                    .num_columns(3)
                    .spacing([8.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Package (.apk / .xapk / .ipa):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.package_path)
                                .hint_text("Optional: drop .apk / .xapk / .apks / .ipa here")
                                .desired_width(540.0),
                        );
                        ui.horizontal(|ui| {
                            if ui.button("Browse...").clicked() {
                                if let Some(p) = rfd::FileDialog::new()
                                    .add_filter("Mobile Packages", &["apk", "xapk", "apks", "ipa"])
                                    .pick_file()
                                {
                                    if is_package_path(&p) {
                                        self.package_path = p.to_string_lossy().into_owned();
                                    }
                                }
                            }
                            if !self.package_path.is_empty() && ui.button("Clear").clicked() {
                                self.package_path.clear();
                            }
                        });
                        ui.end_row();

                        ui.label("Binary (.dll / .so / .dylib / .nso / .wasm):");
                        ui.add(egui::TextEdit::singleline(&mut self.binary_path).desired_width(540.0));
                        if ui.button("Browse...").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("Binaries", &["dll", "so", "dylib", "nso", "wasm"])
                                .pick_file()
                            {
                                self.binary_path = p.to_string_lossy().into_owned();
                            }
                        }
                        ui.end_row();

                        ui.label("Metadata (.dat):");
                        ui.add(egui::TextEdit::singleline(&mut self.metadata_path).desired_width(540.0));
                        if ui.button("Browse...").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("Metadata", &["dat"])
                                .pick_file()
                            {
                                self.metadata_path = p.to_string_lossy().into_owned();
                            }
                        }
                        ui.end_row();

                        ui.label("Output Folder:");
                        ui.add(egui::TextEdit::singleline(&mut self.out_dir).desired_width(540.0));
                        if ui.button("Browse...").clicked() {
                            if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                self.out_dir = p.to_string_lossy().into_owned();
                            }
                        }
                        ui.end_row();

                        ui.label("Profile (.json, optional):");
                        ui.add(egui::TextEdit::singleline(&mut self.profile_path).desired_width(540.0));
                        if ui.button("Browse...").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("JSON Profile", &["json"])
                                .pick_file()
                            {
                                self.profile_path = p.to_string_lossy().into_owned();
                            }
                        }
                        ui.end_row();
                    });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Manual MetaReg VA:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.meta_reg_hex)
                            .hint_text("0x...")
                            .desired_width(120.0),
                    );
                    ui.add_space(10.0);
                    ui.label("Manual CodeReg VA:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.code_reg_hex)
                            .hint_text("0x...")
                            .desired_width(120.0),
                    );
                    ui.add_space(10.0);
                    ui.label("Arch:");
                    egui::ComboBox::from_id_salt("pkg_arch")
                        .selected_text(&self.preferred_arch)
                        .width(100.0)
                        .show_ui(ui, |ui| {
                            for choice in ["auto", "arm64-v8a", "armeabi-v7a", "x86_64"] {
                                ui.selectable_value(&mut self.preferred_arch, choice.to_string(), choice);
                            }
                        });
                    ui.add_space(10.0);
                    ui.checkbox(&mut self.memory_dump_mode, "Memory Dump (1:1 VA)");
                    ui.add_space(10.0);
                    ui.label("Dump Base VA:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.dump_base_hex)
                            .hint_text("0x7... (opt)")
                            .desired_width(110.0),
                    );
                });

                ui.add_space(10.0);
                let has_pkg = !self.package_path.trim().is_empty();
                let has_manual =
                    !self.metadata_path.trim().is_empty() && !self.binary_path.trim().is_empty();
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(
                        !self.is_busy && (has_pkg || !self.metadata_path.trim().is_empty()),
                        |ui| {
                            if ui.button("Run Inspect").clicked() {
                                self.start_inspect(ctx);
                            }
                        },
                    );
                    ui.add_enabled_ui(!self.is_busy && (has_pkg || has_manual), |ui| {
                            let dump_btn = egui::Button::new(
                                egui::RichText::new("Run Full Dump")
                                    .color(egui::Color32::BLACK)
                                    .strong(),
                            )
                            .fill(accent);
                            if ui.add(dump_btn).clicked() {
                                self.start_dump(ctx);
                            }
                        },
                    );
                    if ui.button("Carve Metadata...").clicked() {
                        if let Some(ram_path) = rfd::FileDialog::new().pick_file() {
                            match std::fs::read(&ram_path)
                                .map_err(anyhow::Error::from)
                                .and_then(|b| crate::metadata::carver::carve_metadata_from_blob(&b))
                            {
                                Ok(carved) => {
                                    if let Some(save_path) = rfd::FileDialog::new()
                                        .set_file_name("carved-metadata.dat")
                                        .add_filter("Metadata", &["dat"])
                                        .save_file()
                                    {
                                        if let Err(e) = std::fs::write(&save_path, &carved) {
                                            self.status_text = format!("Save failed: {}", e);
                                        } else {
                                            self.metadata_path =
                                                save_path.to_string_lossy().into_owned();
                                            self.status_text = format!(
                                                "Carved {} bytes -> {}",
                                                carved.len(),
                                                save_path.display()
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    self.status_text = format!("Carve failed: {}", e);
                                }
                            }
                        }
                    }
                    if ui.button("Copy Log").clicked() {
                        ctx.copy_text(self.log_text.clone());
                    }
                    if ui.button("Clear Log").clicked() {
                        self.log_text.clear();
                    }
                });
            });

        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("log_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.log_text.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(20),
                );
            });
    }

    fn render_explorer_tab(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let accent = self.theme.accent();
        let cyan = egui::Color32::from_rgb(0, 242, 160);
        let amber = egui::Color32::from_rgb(251, 197, 49);

        ui.horizontal(|ui| {
            if ui.button("Load dump.cs...").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("C# Dump", &["cs"])
                    .pick_file()
                {
                    self.start_load_explorer_file(ctx, p);
                }
            }
            ui.label("Search:");
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.explorer_search)
                    .hint_text("Class, Namespace, Field, Method...")
                    .desired_width(280.0),
            );
            if resp.changed() {
                self.rebuild_explorer_filter();
            }
            ui.label(
                egui::RichText::new(format!(
                    "{} / {} classes ({})",
                    self.filtered_indices.len(),
                    self.explorer_classes.len(),
                    self.explorer_source
                ))
                .color(egui::Color32::GRAY),
            );
        });
        ui.separator();

        egui::SidePanel::left("explorer_cls_list")
            .resizable(true)
            .default_width(340.0)
            .frame(
                egui::Frame::NONE
                    .fill(self.theme.surface())
                    .inner_margin(6.0)
                    .stroke(egui::Stroke::new(1.0_f32, self.theme.panel_border())),
            )
            .show_inside(ui, |ui| {
                let row_h = 22.0;
                let total = self.filtered_indices.len();
                egui::ScrollArea::vertical()
                    .id_salt("cls_scroll")
                    .auto_shrink([false, false])
                    .show_rows(ui, row_h, total, |ui, range| {
                        for pos in range {
                            let cls_idx = self.filtered_indices[pos];
                            let cls = &self.explorer_classes[cls_idx];
                            let label = if cls.namespace.is_empty() {
                                cls.name.clone()
                            } else {
                                format!("{}.{}", cls.namespace, cls.name)
                            };
                            let selected = self.selected_filtered_pos == Some(pos);
                            if ui.selectable_label(selected, label).clicked() {
                                self.selected_filtered_pos = Some(pos);
                            }
                        }
                    });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(self.theme.base()).inner_margin(10.0))
            .show_inside(ui, |ui| {
                let Some(pos) = self.selected_filtered_pos else {
                    ui.label("Load or generate a dump.cs to inspect classes, offsets, and RVAs.");
                    return;
                };
                let Some(&cls_idx) = self.filtered_indices.get(pos) else {
                    return;
                };
                let cls = &self.explorer_classes[cls_idx];

                ui.horizontal(|ui| {
                    let full = if cls.namespace.is_empty() {
                        cls.name.clone()
                    } else {
                        format!("{}.{}", cls.namespace, cls.name)
                    };
                    ui.label(egui::RichText::new(full).strong().size(17.0).color(accent));
                    if ui.button("Copy C++ Offsets (#define)").clicked() {
                        ctx.copy_text(format_cpp_offsets(cls));
                    }
                });
                ui.separator();

                egui::ScrollArea::vertical()
                    .id_salt("cls_detail_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(format!("Fields ({})", cls.fields.len()))
                                .strong()
                                .color(amber),
                        );
                        egui::Grid::new("fields_tbl")
                            .striped(true)
                            .spacing([12.0, 4.0])
                            .show(ui, |ui| {
                                for f in &cls.fields {
                                    let off_s = f
                                        .offset
                                        .map(|o| format!("0x{:X}", o))
                                        .unwrap_or_else(|| "-".to_string());
                                    let static_s = if f.is_static { "static" } else { "" };
                                    ui.label(egui::RichText::new(&f.field_type).monospace().color(cyan));
                                    ui.label(egui::RichText::new(&f.name).monospace());
                                    ui.label(egui::RichText::new(&off_s).monospace().color(amber));
                                    ui.label(egui::RichText::new(static_s).monospace().color(egui::Color32::GRAY));
                                    if ui.small_button("Copy").clicked() {
                                        if let Some(o) = f.offset {
                                            ctx.copy_text(format!("0x{:X}", o));
                                        }
                                    }
                                    ui.end_row();
                                }
                            });

                        ui.add_space(12.0);
                        ui.label(
                            egui::RichText::new(format!("Methods ({})", cls.methods.len()))
                                .strong()
                                .color(cyan),
                        );
                        egui::Grid::new("methods_tbl")
                            .striped(true)
                            .spacing([12.0, 4.0])
                            .show(ui, |ui| {
                                for m in &cls.methods {
                                    let rva_s = m
                                        .rva
                                        .map(|r| format!("0x{:X}", r))
                                        .unwrap_or_else(|| "-".to_string());
                                    ui.label(egui::RichText::new(&rva_s).monospace().color(amber));
                                    ui.label(egui::RichText::new(&m.signature).monospace());
                                    if ui.small_button("Copy RVA").clicked() {
                                        if let Some(r) = m.rva {
                                            ctx.copy_text(format!("0x{:X}", r));
                                        }
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            });
    }

    fn render_diff_tab(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let accent = self.theme.accent();
        egui::Frame::NONE
            .fill(self.theme.surface())
            .stroke(egui::Stroke::new(1.0_f32, self.theme.panel_border()))
            .corner_radius(6.0)
            .inner_margin(12.0)
            .show(ui, |ui| {
                egui::Grid::new("diff_grid")
                    .num_columns(3)
                    .spacing([8.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Old dump.cs:");
                        ui.add(egui::TextEdit::singleline(&mut self.diff_old_path).desired_width(560.0));
                        if ui.button("Browse...").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("C# Dump", &["cs"])
                                .pick_file()
                            {
                                self.diff_old_path = p.to_string_lossy().into_owned();
                            }
                        }
                        ui.end_row();

                        ui.label("New dump.cs:");
                        ui.add(egui::TextEdit::singleline(&mut self.diff_new_path).desired_width(560.0));
                        if ui.button("Browse...").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("C# Dump", &["cs"])
                                .pick_file()
                            {
                                self.diff_new_path = p.to_string_lossy().into_owned();
                            }
                        }
                        ui.end_row();

                        ui.label("Class filter (optional):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.diff_filter)
                                .hint_text("e.g. BattleManager")
                                .desired_width(560.0),
                        );
                        ui.label("");
                        ui.end_row();
                    });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.diff_only_changed, "Only changed");
                    ui.checkbox(&mut self.diff_emit_cpp, "Emit C++ #define");
                    ui.add_space(16.0);
                    ui.add_enabled_ui(
                        !self.is_busy
                            && !self.diff_old_path.trim().is_empty()
                            && !self.diff_new_path.trim().is_empty(),
                        |ui| {
                            let btn = egui::Button::new(
                                egui::RichText::new("Run Diff")
                                    .color(egui::Color32::BLACK)
                                    .strong(),
                            )
                            .fill(accent);
                            if ui.add(btn).clicked() {
                                self.start_diff(ctx);
                            }
                        },
                    );
                    if ui.button("Copy Diff").clicked() {
                        ctx.copy_text(self.diff_output.clone());
                    }
                    if !self.diff_summary.is_empty() {
                        ui.label(egui::RichText::new(&self.diff_summary).strong().color(accent));
                    }
                });
            });

        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("diff_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.diff_output.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(22),
                );
            });
    }

    fn render_profile_tab(&mut self, ui: &mut egui::Ui) {
        let accent = self.theme.accent();
        egui::Frame::NONE
            .fill(self.theme.surface())
            .stroke(egui::Stroke::new(1.0_f32, self.theme.panel_border()))
            .corner_radius(6.0)
            .inner_margin(12.0)
            .show(ui, |ui| {
                egui::Grid::new("prof_grid")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Profile Name:");
                        ui.add(egui::TextEdit::singleline(&mut self.prof_name).desired_width(360.0));
                        ui.end_row();

                        ui.label("Header Offset (bytes):");
                        ui.add(egui::TextEdit::singleline(&mut self.prof_header_offset).desired_width(360.0));
                        ui.end_row();

                        ui.label("XOR Key (hex, optional):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.prof_xor_key)
                                .hint_text("e.g. 5AA5")
                                .desired_width(360.0),
                        );
                        ui.end_row();

                        ui.label("Expected Custom Magic (hex, optional):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.prof_expected_magic)
                                .hint_text("e.g. 0x12345678")
                                .desired_width(360.0),
                        );
                        ui.end_row();

                        ui.label("Override Version (optional):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.prof_override_version)
                                .hint_text("e.g. 29 or 1024")
                                .desired_width(360.0),
                        );
                        ui.end_row();

                        ui.label("Header Engine Mode:");
                        egui::ComboBox::from_id_salt("hdr_mode")
                            .selected_text(match self.prof_header_mode {
                                HeaderModeChoice::Auto => "Auto",
                                HeaderModeChoice::Standard => "standard",
                                HeaderModeChoice::Adaptive => "adaptive",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.prof_header_mode, HeaderModeChoice::Auto, "Auto");
                                ui.selectable_value(&mut self.prof_header_mode, HeaderModeChoice::Standard, "standard");
                                ui.selectable_value(&mut self.prof_header_mode, HeaderModeChoice::Adaptive, "adaptive");
                            });
                        ui.end_row();

                        ui.label("Register Symbol (Adaptive ELF):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.prof_register_symbol)
                                .desired_width(360.0),
                        );
                        ui.end_row();
                    });

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Load Profile JSON...").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("JSON Profile", &["json"])
                            .pick_file()
                        {
                            match DumpProfile::load(&p) {
                                Ok(prof) => {
                                    self.prof_name = prof.name;
                                    self.prof_header_offset = prof.header_offset.to_string();
                                    self.prof_xor_key = prof.xor_key_hex.unwrap_or_default();
                                    self.prof_expected_magic = prof
                                        .expected_magic
                                        .map(|m| format!("0x{:08X}", m))
                                        .unwrap_or_default();
                                    self.prof_override_version =
                                        prof.override_version.map(|v| v.to_string()).unwrap_or_default();
                                    self.prof_header_mode = match prof.header_mode.as_deref() {
                                        Some("standard") => HeaderModeChoice::Standard,
                                        Some("adaptive") => HeaderModeChoice::Adaptive,
                                        _ => HeaderModeChoice::Auto,
                                    };
                                    self.prof_register_symbol = prof.register_symbol.unwrap_or_default();
                                    self.profile_path = p.to_string_lossy().into_owned();
                                    self.status_text = format!("Loaded profile: {}", p.display());
                                }
                                Err(e) => {
                                    self.status_text = format!("Invalid profile: {}", e);
                                }
                            }
                        }
                    }

                    let save_btn = egui::Button::new(
                        egui::RichText::new("Save Profile JSON & Use in Dump")
                            .color(egui::Color32::BLACK)
                            .strong(),
                    )
                    .fill(accent);
                    if ui.add(save_btn).clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .set_file_name("profile.json")
                            .add_filter("JSON Profile", &["json"])
                            .save_file()
                        {
                            let prof = DumpProfile {
                                name: self.prof_name.clone(),
                                header_offset: self.prof_header_offset.trim().parse().unwrap_or(0),
                                xor_key_hex: (!self.prof_xor_key.trim().is_empty())
                                    .then(|| self.prof_xor_key.trim().to_string()),
                                xor_range: None,
                                expected_magic: (!self.prof_expected_magic.trim().is_empty())
                                    .then(|| parse_hex_u64(&self.prof_expected_magic).ok())
                                    .flatten()
                                    .map(|v| v as u32),
                                override_version: self.prof_override_version.trim().parse().ok(),
                                header_mode: match self.prof_header_mode {
                                    HeaderModeChoice::Auto => None,
                                    HeaderModeChoice::Standard => Some("standard".to_string()),
                                    HeaderModeChoice::Adaptive => Some("adaptive".to_string()),
                                },
                                register_symbol: (!self.prof_register_symbol.trim().is_empty())
                                    .then(|| self.prof_register_symbol.trim().to_string()),
                            };
                            match serde_json::to_string_pretty(&prof) {
                                Ok(json) => {
                                    if let Err(e) = std::fs::write(&p, json) {
                                        self.status_text = format!("Failed to save profile: {}", e);
                                    } else {
                                        self.profile_path = p.to_string_lossy().into_owned();
                                        self.status_text = format!("Saved profile to {}", p.display());
                                    }
                                }
                                Err(e) => self.status_text = format!("Serialize error: {}", e),
                            }
                        }
                    }
                });
            });
    }
}

impl eframe::App for DumperApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_dropped_files(ctx);
        self.poll_worker();
        if self.is_busy {
            ctx.request_repaint();
        }

        self.render_top_bar(ctx);
        self.render_status_bar(ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(self.theme.base()).inner_margin(12.0))
            .show(ctx, |ui| match self.tab {
                ActiveTab::DumpInspect => self.render_dump_inspect_tab(ctx, ui),
                ActiveTab::Explorer => self.render_explorer_tab(ctx, ui),
                ActiveTab::Diff => self.render_diff_tab(ctx, ui),
                ActiveTab::Profile => self.render_profile_tab(ui),
            });
    }
}

fn format_cpp_offsets(cls: &ParsedClass) -> String {
    let mut out = String::new();
    let cname = sanitize_c_ident(&cls.name);
    let _ = writeln!(out, "// {}.{}", cls.namespace, cls.name);
    for f in &cls.fields {
        if let Some(off) = f.offset {
            let _ = writeln!(
                out,
                "#define {}_{} 0x{:X} // {}",
                cname,
                sanitize_c_ident(&f.name),
                off,
                f.field_type
            );
        }
    }
    if !cls.fields.is_empty() {
        let _ = writeln!(out, "\nnamespace Offsets_{} {{", cname);
        for f in &cls.fields {
            if let Some(off) = f.offset {
                let _ = writeln!(
                    out,
                    "    constexpr uintptr_t {} = 0x{:X};",
                    sanitize_c_ident(&f.name),
                    off
                );
            }
        }
        for m in &cls.methods {
            if let Some(rva) = m.rva {
                let _ = writeln!(
                    out,
                    "    constexpr uintptr_t RVA_{} = 0x{:X};",
                    sanitize_c_ident(&m.name),
                    rva
                );
            }
        }
        let _ = writeln!(out, "}}");
    }
    out
}

fn apply_theme_visuals(ctx: &egui::Context, theme: GuiTheme) {
    let mut visuals = egui::Visuals::dark();
    let base = theme.base();
    let surface = theme.surface();
    let accent = theme.accent();
    visuals.window_fill = base;
    visuals.panel_fill = base;
    visuals.extreme_bg_color = surface;
    visuals.faint_bg_color = surface;
    visuals.selection.bg_fill = accent.gamma_multiply(0.35);
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, accent);
    visuals.widgets.inactive.bg_fill = surface;
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, accent);
    ctx.set_visuals(visuals);
}

pub fn run_gui() -> Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "il2cpp-dumper-rs",
        opts,
        Box::new(|cc| Ok(Box::new(DumperApp::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {}", e))?;
    Ok(())
}
