//! PNG charts drawn from the M1 tables.
//!
//! Charts follow one visual system:
//!
//! - light chart surface with ink-coloured text, hairline solid gridlines and 2 px lines;
//! - markers at least 8 px wide with a surface-coloured ring;
//! - a legend whenever two or more series are shown;
//! - one y-axis per panel, with small multiples when magnitudes differ.
//!
//! Ordered series (genesis size, committee size, online fraction, restart cost) use steps of
//! one blue ramp; unordered pairs use the first categorical slots. Both colour sets were
//! checked with a colour-vision-deficiency validator. Text is rendered with the bundled
//! DejaVu Sans font, so output does not depend on fonts installed on the machine.
//!
//! The renderer only draws; every value comes from a table the CLI also writes to CSV. Points
//! on a log axis are passed as base-10 logarithms, which keeps probabilities far below the
//! `f64` range drawable.

use gb_analytic::M1Results;
use gb_analytic::witness::KwcState;
use plotters::prelude::*;
use plotters::style::text_anchor::{HPos, Pos, VPos};
use plotters::style::{FontStyle, register_font};
use std::path::Path;
use std::sync::OnceLock;

const FONT: &[u8] = include_bytes!("../assets/fonts/DejaVuSans.ttf");
const FAMILY: &str = "sans-serif";

const SURFACE: RGBColor = RGBColor(0xfc, 0xfc, 0xfb);
const INK: RGBColor = RGBColor(0x0b, 0x0b, 0x0b);
const INK_SECONDARY: RGBColor = RGBColor(0x52, 0x51, 0x4e);
const MUTED: RGBColor = RGBColor(0x89, 0x87, 0x81);
const GRID: RGBColor = RGBColor(0xe1, 0xe0, 0xd9);
const AXIS: RGBColor = RGBColor(0xc3, 0xc2, 0xb7);
const CATEGORICAL: [RGBColor; 3] = [
    RGBColor(0x2a, 0x78, 0xd6),
    RGBColor(0xeb, 0x68, 0x34),
    RGBColor(0x1b, 0xaf, 0x7a),
];
const RAMP_3: [RGBColor; 3] = [
    RGBColor(0x86, 0xb6, 0xef),
    RGBColor(0x2a, 0x78, 0xd6),
    RGBColor(0x0d, 0x36, 0x6b),
];
const RAMP_4: [RGBColor; 4] = [
    RGBColor(0x86, 0xb6, 0xef),
    RGBColor(0x39, 0x87, 0xe5),
    RGBColor(0x1c, 0x5c, 0xab),
    RGBColor(0x0d, 0x36, 0x6b),
];
const RAMP_5: [RGBColor; 5] = [
    RGBColor(0x86, 0xb6, 0xef),
    RGBColor(0x55, 0x98, 0xe7),
    RGBColor(0x2a, 0x78, 0xd6),
    RGBColor(0x1c, 0x5c, 0xab),
    RGBColor(0x0d, 0x36, 0x6b),
];

/// Colours for `n` ordered series, light to dark (at most five).
fn ramp(n: usize) -> &'static [RGBColor] {
    match n {
        0..=1 => &RAMP_3[1..2],
        2 => &RAMP_3[1..3],
        3 => &RAMP_3,
        4 => &RAMP_4,
        _ => &RAMP_5,
    }
}

/// Axis scale. Points on a `Log10` axis are given as base-10 logarithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scale {
    /// Linear axis.
    Linear,
    /// Logarithmic axis; values are base-10 logarithms.
    Log10,
}

/// One plotted series.
#[derive(Debug, Clone)]
pub struct Series {
    /// Legend label.
    pub label: String,
    /// Points in axis units.
    pub points: Vec<(f64, f64)>,
    /// Line and marker colour.
    pub color: RGBColor,
    /// Whether to draw a marker at each point.
    pub markers: bool,
}

/// A labelled horizontal reference line.
#[derive(Debug, Clone)]
pub struct Reference {
    /// Label drawn at the right end of the line.
    pub label: String,
    /// Height in y-axis units.
    pub value: f64,
}

/// One chart panel.
#[derive(Debug, Clone)]
pub struct Panel {
    /// Panel title.
    pub title: String,
    /// X-axis description.
    pub x_label: String,
    /// Y-axis description.
    pub y_label: String,
    /// X-axis scale.
    pub x_scale: Scale,
    /// Y-axis scale.
    pub y_scale: Scale,
    /// Series to draw.
    pub series: Vec<Series>,
    /// Reference lines.
    pub references: Vec<Reference>,
    /// Legend position.
    pub legend: SeriesLabelPosition,
    /// Fixed y range, or `None` to fit the data.
    pub y_range: Option<(f64, f64)>,
}

/// A figure: a title, a subtitle and one or more panels side by side.
#[derive(Debug, Clone)]
pub struct Figure {
    /// Figure title.
    pub title: String,
    /// One-line subtitle.
    pub subtitle: String,
    /// Panels, left to right.
    pub panels: Vec<Panel>,
    /// Image size in pixels.
    pub size: (u32, u32),
}

fn register_fonts() -> anyhow::Result<()> {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    let ok = *REGISTERED.get_or_init(|| {
        register_font(FAMILY, FontStyle::Normal, FONT).is_ok()
            && register_font(FAMILY, FontStyle::Bold, FONT).is_ok()
    });
    anyhow::ensure!(ok, "the bundled font could not be registered");
    Ok(())
}

fn plot_error<E: std::fmt::Display>(error: E) -> anyhow::Error {
    anyhow::anyhow!("chart drawing failed: {error}")
}

/// Draws `figure` as a PNG at `path`.
pub fn draw_figure(path: &Path, figure: &Figure) -> anyhow::Result<()> {
    register_fonts()?;
    let root = BitMapBackend::new(path, figure.size).into_drawing_area();
    root.fill(&SURFACE).map_err(plot_error)?;
    let (header, body) = root.split_vertically(84);
    header
        .draw(&Text::new(
            figure.title.as_str(),
            (28, 16),
            (FAMILY, 26).into_font().color(&INK),
        ))
        .map_err(plot_error)?;
    header
        .draw(&Text::new(
            figure.subtitle.as_str(),
            (28, 52),
            (FAMILY, 16).into_font().color(&INK_SECONDARY),
        ))
        .map_err(plot_error)?;
    let areas = body.split_evenly((1, figure.panels.len().max(1)));
    for (area, panel) in areas.iter().zip(&figure.panels) {
        draw_panel(area, panel)?;
    }
    root.present().map_err(plot_error)?;
    Ok(())
}

fn data_range(panel: &Panel, pick: impl Fn(&(f64, f64)) -> f64) -> (f64, f64) {
    let values = panel.series.iter().flat_map(|s| s.points.iter().map(&pick));
    values.fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), v| {
        (lo.min(v), hi.max(v))
    })
}

fn padded(range: (f64, f64), scale: Scale, include: &[f64]) -> (f64, f64) {
    let (mut lo, mut hi) = include
        .iter()
        .fold(range, |(lo, hi), v| (lo.min(*v), hi.max(*v)));
    if !lo.is_finite() || !hi.is_finite() {
        return (0.0, 1.0);
    }
    match scale {
        Scale::Log10 => {
            lo = lo.floor();
            hi = hi.ceil();
            if hi - lo < 1.0 {
                hi = lo + 1.0;
            }
        }
        Scale::Linear => {
            let pad = if hi > lo { 0.05 * (hi - lo) } else { 1.0 };
            lo -= pad;
            hi += pad;
        }
    }
    (lo, hi)
}

fn draw_panel(
    area: &DrawingArea<BitMapBackend<'_>, plotters::coord::Shift>,
    panel: &Panel,
) -> anyhow::Result<()> {
    let x_range = padded(data_range(panel, |p| p.0), panel.x_scale, &[]);
    let references: Vec<f64> = panel.references.iter().map(|r| r.value).collect();
    let y_range = panel
        .y_range
        .unwrap_or_else(|| padded(data_range(panel, |p| p.1), panel.y_scale, &references));
    let right_margin = if panel.references.is_empty() { 18 } else { 118 };
    let mut chart = ChartBuilder::on(area)
        .caption(panel.title.as_str(), (FAMILY, 19).into_font().color(&INK))
        .margin(18)
        .margin_right(right_margin)
        .x_label_area_size(52)
        .y_label_area_size(84)
        .build_cartesian_2d(x_range.0..x_range.1, y_range.0..y_range.1)
        .map_err(plot_error)?;
    let x_format = |v: &f64| tick_label(*v, panel.x_scale);
    let y_format = |v: &f64| tick_label(*v, panel.y_scale);
    chart
        .configure_mesh()
        .disable_x_mesh()
        .max_light_lines(0)
        .bold_line_style(GRID.stroke_width(1))
        .axis_style(AXIS.stroke_width(1))
        .x_labels(8)
        .y_labels(8)
        .x_label_formatter(&x_format)
        .y_label_formatter(&y_format)
        .label_style((FAMILY, 14).into_font().color(&MUTED))
        .axis_desc_style((FAMILY, 15).into_font().color(&INK_SECONDARY))
        .x_desc(panel.x_label.as_str())
        .y_desc(panel.y_label.as_str())
        .draw()
        .map_err(plot_error)?;
    let base = area.get_base_pixel();
    for reference in &panel.references {
        let line = [(x_range.0, reference.value), (x_range.1, reference.value)];
        chart
            .draw_series(LineSeries::new(line, MUTED.stroke_width(1)))
            .map_err(plot_error)?;
        // The label sits in the right margin, outside the plot, so it never covers data.
        let (x, y) = chart.backend_coord(&(x_range.1, reference.value));
        let style = (FAMILY, 13)
            .into_font()
            .color(&INK_SECONDARY)
            .pos(Pos::new(HPos::Left, VPos::Center));
        area.draw(&Text::new(
            reference.label.clone(),
            (x - base.0 + 8, y - base.1),
            style,
        ))
        .map_err(plot_error)?;
    }
    for series in &panel.series {
        let color = series.color;
        chart
            .draw_series(LineSeries::new(
                series.points.clone(),
                color.stroke_width(2),
            ))
            .map_err(plot_error)?
            .label(series.label.as_str())
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 22, y)], color.stroke_width(3))
            });
        if series.markers {
            chart
                .draw_series(
                    series
                        .points
                        .iter()
                        .map(|p| Circle::new(*p, 6, SURFACE.filled())),
                )
                .map_err(plot_error)?;
            chart
                .draw_series(
                    series
                        .points
                        .iter()
                        .map(|p| Circle::new(*p, 4, color.filled())),
                )
                .map_err(plot_error)?;
        }
    }
    if panel.series.len() >= 2 {
        chart
            .configure_series_labels()
            .position(panel.legend.clone())
            .margin(12)
            .background_style(SURFACE.mix(0.92))
            .border_style(GRID)
            .label_font((FAMILY, 14).into_font().color(&INK))
            .draw()
            .map_err(plot_error)?;
    }
    Ok(())
}

/// Tick label for an axis value.
pub fn tick_label(value: f64, scale: Scale) -> String {
    match scale {
        Scale::Linear => compact_number(value),
        Scale::Log10 => {
            let rounded = value.round();
            if (value - rounded).abs() > 1e-9 {
                String::new()
            } else if (-3.0..=6.0).contains(&rounded) {
                compact_number(libm::pow(10.0, rounded))
            } else {
                format!("10{}", superscript(rounded as i64))
            }
        }
    }
}

/// A number with thousands separators and at most three decimals, trailing zeros removed.
pub fn compact_number(value: f64) -> String {
    if value.abs() >= 1_000.0 {
        let rounded = value.round() as i64;
        let digits = rounded.unsigned_abs().to_string();
        let mut grouped = String::new();
        for (i, c) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i) % 3 == 0 {
                grouped.push(',');
            }
            grouped.push(c);
        }
        if rounded < 0 {
            format!("-{grouped}")
        } else {
            grouped
        }
    } else {
        let text = format!("{value:.3}");
        let trimmed = text.trim_end_matches('0').trim_end_matches('.');
        if trimmed == "-0" {
            "0".to_string()
        } else {
            trimmed.to_string()
        }
    }
}

/// An integer written with Unicode superscript digits, for example `⁻¹²`.
pub fn superscript(exponent: i64) -> String {
    exponent
        .to_string()
        .chars()
        .map(|c| match c {
            '-' => '⁻',
            '0' => '⁰',
            '1' => '¹',
            '2' => '²',
            '3' => '³',
            '4' => '⁴',
            '5' => '⁵',
            '6' => '⁶',
            '7' => '⁷',
            '8' => '⁸',
            _ => '⁹',
        })
        .collect()
}

/// Short form of a count, for example `2.1M` or `600`.
pub fn short_count(n: u64) -> String {
    if n >= 1_000_000 {
        compact_number(n as f64 / 1_000_000.0) + "M"
    } else if n >= 10_000 {
        compact_number(n as f64 / 1_000.0) + "k"
    } else {
        n.to_string()
    }
}

fn percent(x: f64) -> String {
    format!("{}%", compact_number(100.0 * x))
}

fn log10_points(points: impl Iterator<Item = (f64, f64)>) -> Vec<(f64, f64)> {
    points
        .filter(|(_, y)| *y > 0.0)
        .map(|(x, y)| (x, libm::log10(y)))
        .collect()
}

/// Distinct values in first-seen order.
fn distinct(values: impl Iterator<Item = f64>) -> Vec<f64> {
    let mut seen: Vec<f64> = Vec::new();
    for v in values {
        if !seen.contains(&v) {
            seen.push(v);
        }
    }
    seen
}

/// The wanted values that are present, or else up to `max` evenly spaced values.
fn pick(values: &[f64], wanted: &[f64], max: usize) -> Vec<f64> {
    let present: Vec<f64> = wanted
        .iter()
        .copied()
        .filter(|w| values.contains(w))
        .collect();
    if present.len() >= 2 || values.len() < 2 {
        return present.into_iter().take(max).collect();
    }
    let step = (values.len() - 1) as f64 / (max.min(values.len()) - 1).max(1) as f64;
    (0..max.min(values.len()))
        .map(|i| values[(i as f64 * step).round() as usize])
        .collect()
}

fn thresholds_as_references(thresholds: &[f64]) -> Vec<Reference> {
    thresholds
        .iter()
        .map(|t| Reference {
            label: percent(*t),
            value: *t,
        })
        .collect()
}

/// File names of every chart.
pub const CHART_FILES: &[&str] = &[
    "A1_time_to_threshold.png",
    "A4_adaptive_cap.png",
    "A5_share_trajectories.png",
    "A6_genesis_to_issue.png",
    "A7_long_run_share.png",
    "B1_kwc_probabilities.png",
    "B4_kwc_compositions_10y.png",
    "C1_cac_probabilities.png",
    "D1_restart_advantage.png",
];

/// Draws every chart into `dir`.
pub fn draw_all(dir: &Path, results: &M1Results) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let figures = [
        time_to_threshold(results),
        adaptive_cap(results),
        share_trajectories(results),
        genesis_to_issue(results),
        long_run_share(results),
        kwc_probabilities(results),
        kwc_compositions(results),
        cac_probabilities(results),
        restart_advantage(results),
    ];
    for (name, figure) in CHART_FILES.iter().zip(figures) {
        draw_figure(&dir.join(name), &figure)?;
    }
    Ok(())
}

fn time_to_threshold(results: &M1Results) -> Figure {
    let rows = &results.a.thresholds;
    let thresholds = distinct(rows.iter().map(|r| r.threshold));
    let all_genesis = distinct(rows.iter().map(|r| r.genesis_ids as f64));
    let genesis = pick(
        &all_genesis,
        &[500_000.0, 1_000_000.0, 2_100_000.0, 3_000_000.0],
        4,
    );
    let colors = ramp(genesis.len());
    let panels = thresholds
        .iter()
        .map(|t| Panel {
            title: format!("Threshold T = {}", percent(*t)),
            x_label: "attacker share of new IDs, s".to_string(),
            y_label: "years (log scale)".to_string(),
            x_scale: Scale::Linear,
            y_scale: Scale::Log10,
            series: genesis
                .iter()
                .zip(colors.iter().cycle())
                .map(|(g, color)| Series {
                    label: format!("G = {}", short_count(*g as u64)),
                    points: log10_points(
                        rows.iter()
                            .filter(|r| r.threshold == *t && r.genesis_ids as f64 == *g)
                            .filter_map(|r| r.years.map(|y| (r.attacker_share, y))),
                    ),
                    color: *color,
                    markers: true,
                })
                .collect(),
            references: Vec::new(),
            legend: SeriesLabelPosition::UpperRight,
            y_range: None,
        })
        .collect();
    Figure {
        title: "Years until an attacker holds a share T of active IDs".to_string(),
        subtitle: "Base model: attacker wins share s of new IDs; G = historical active base (all five sizes are in A1_time_to_threshold.csv). Shares s ≤ T never reach T.".to_string(),
        panels,
        size: (1800, 640),
    }
}

fn adaptive_cap(results: &M1Results) -> Figure {
    let floor = results
        .a
        .safety
        .first()
        .map(|r| r.threshold)
        .unwrap_or(0.51);
    let rows: Vec<_> = results
        .a
        .cap
        .iter()
        .filter(|r| r.attacker_share == 1.0 && r.threshold == floor)
        .collect();
    let continuous = rows
        .iter()
        .find(|r| r.model == "continuous")
        .and_then(|r| r.time_in_t_min);
    let frozen = rows
        .iter()
        .find(|r| r.model == "frozen")
        .and_then(|r| r.time_in_t_min);
    let series_for =
        |model: &str| -> Vec<(f64, f64)> {
            continuous
                .map(|c| (0.0, c))
                .into_iter()
                .chain(rows.iter().filter(|r| r.model == model).filter_map(|r| {
                    Some((r.checkpoint_interval_fraction_of_t_min?, r.time_in_t_min?))
                }))
                .collect()
        };
    let mut references = vec![Reference {
        label: "floor (T_min)".to_string(),
        value: 1.0,
    }];
    if let Some(f) = frozen {
        references.push(Reference {
            label: "frozen cap".to_string(),
            value: f,
        });
    }
    Figure {
        title: "Adaptive cap: time for a 100%-capture attacker to reach 51%".to_string(),
        subtitle: "Worst-case bound. x = 0 is a continuously updated cap; other points recalculate it at checkpoints. \"Frozen cap\": rate fixed at attack start.".to_string(),
        panels: vec![Panel {
            title: "Time to majority, in units of T_min".to_string(),
            x_label: "checkpoint interval (fraction of T_min)".to_string(),
            y_label: "time / T_min".to_string(),
            x_scale: Scale::Linear,
            y_scale: Scale::Linear,
            series: vec![
                Series {
                    label: "attack starts at a checkpoint".to_string(),
                    points: series_for("checkpoint aligned"),
                    color: CATEGORICAL[0],
                    markers: true,
                },
                Series {
                    label: "attack starts at the worst moment".to_string(),
                    points: series_for("checkpoint worst phase"),
                    color: CATEGORICAL[1],
                    markers: true,
                },
            ],
            references,
            legend: SeriesLabelPosition::LowerRight,
            y_range: Some((0.0, 1.2)),
        }],
        size: (1200, 760),
    }
}

fn share_trajectories(results: &M1Results) -> Figure {
    let rows = &results.a.trajectories;
    let shares = distinct(rows.iter().map(|r| r.attacker_share));
    let chosen = pick(&shares, &[0.25, 0.4, 0.52, 0.6, 1.0], 5);
    let colors = ramp(chosen.len());
    let genesis = rows.first().map(|r| r.genesis_ids).unwrap_or(0);
    let thresholds = distinct(results.a.thresholds.iter().map(|r| r.threshold));
    Figure {
        title: "Attacker share of active IDs over time".to_string(),
        subtitle: format!(
            "Base model, historical active base G = {}. Each line is one sustained share s of new IDs.",
            short_count(genesis)
        ),
        panels: vec![Panel {
            title: "Share of active IDs".to_string(),
            x_label: "years since the attack started".to_string(),
            y_label: "attacker share of active IDs".to_string(),
            x_scale: Scale::Linear,
            y_scale: Scale::Linear,
            series: chosen
                .iter()
                .zip(colors)
                .map(|(s, color)| Series {
                    label: format!("s = {}", percent(*s)),
                    points: rows
                        .iter()
                        .filter(|r| r.attacker_share == *s)
                        .map(|r| (r.year, r.share_of_active_ids))
                        .collect(),
                    color: *color,
                    markers: false,
                })
                .collect(),
            references: thresholds_as_references(&thresholds),
            legend: SeriesLabelPosition::LowerRight,
            y_range: Some((0.0, 1.0)),
        }],
        size: (1200, 760),
    }
}

fn genesis_to_issue(results: &M1Results) -> Figure {
    let rows = &results.a.genesis;
    let floors = distinct(rows.iter().map(|r| r.t_min_years));
    let colors = ramp(floors.len());
    let max_issue = rows
        .iter()
        .map(|r| r.genesis_ids_to_issue / 1e6)
        .fold(1.0, f64::max);
    Figure {
        title: "Genesis IDs to issue for the time floor at the fixed 30 s rate".to_string(),
        subtitle: "Worst-case bound: a 100%-capture attacker needs at least T_min to reach 51% only while enough genesis IDs stay active.".to_string(),
        panels: vec![Panel {
            title: "Genesis IDs to issue (millions)".to_string(),
            x_label: "fraction of genesis IDs that stay active".to_string(),
            y_label: "genesis IDs to issue (millions)".to_string(),
            x_scale: Scale::Linear,
            y_scale: Scale::Linear,
            series: floors
                .iter()
                .zip(colors.iter().cycle())
                .map(|(t, color)| Series {
                    label: format!("T_min = {} yr", compact_number(*t)),
                    points: rows
                        .iter()
                        .filter(|r| r.t_min_years == *t)
                        .map(|r| (r.online_fraction, r.genesis_ids_to_issue / 1e6))
                        .collect(),
                    color: *color,
                    markers: true,
                })
                .collect(),
            references: vec![Reference {
                label: "default 2.1M".to_string(),
                value: 2.1,
            }],
            legend: SeriesLabelPosition::UpperRight,
            y_range: Some((0.0, 1.08 * max_issue)),
        }],
        size: (1200, 760),
    }
}

fn long_run_share(results: &M1Results) -> Figure {
    let rows = &results.a.long_run;
    let online = distinct(rows.iter().map(|r| r.online_fraction));
    let chosen = pick(&online, &[0.5, 0.7, 0.9, 1.0], 4);
    let colors = ramp(chosen.len());
    let thresholds = distinct(results.a.thresholds.iter().map(|r| r.threshold));
    Figure {
        title: "Share of active IDs an attacker settles at".to_string(),
        subtitle: "Realistic online fraction: a fraction f of all honest IDs, old and new, is online. Long-run share = s / (s + f(1 − s)).".to_string(),
        panels: vec![Panel {
            title: "Long-run attacker share of active IDs".to_string(),
            x_label: "attacker share of new IDs, s".to_string(),
            y_label: "long-run share of active IDs".to_string(),
            x_scale: Scale::Linear,
            y_scale: Scale::Linear,
            series: chosen
                .iter()
                .zip(colors)
                .map(|(f, color)| Series {
                    label: format!("f = {}", percent(*f)),
                    points: rows
                        .iter()
                        .filter(|r| r.online_fraction == *f)
                        .map(|r| (r.attacker_share, r.long_run_share))
                        .collect(),
                    color: *color,
                    markers: true,
                })
                .collect(),
            references: thresholds_as_references(&thresholds),
            legend: SeriesLabelPosition::UpperLeft,
            y_range: Some((0.0, 1.0)),
        }],
        size: (1200, 760),
    }
}

fn kwc_probabilities(results: &M1Results) -> Figure {
    let rows: Vec<_> = results
        .b
        .kwc
        .iter()
        .filter(|r| r.layout == "40-node" && r.model == "hypergeometric" && r.kwcs == Some(100_000))
        .collect();
    let panel = |state: KwcState, title: &str, kinds: &[(&str, &str)]| Panel {
        title: title.to_string(),
        x_label: "attacker fraction of registered IDs, p".to_string(),
        y_label: "probability per KWC (log scale)".to_string(),
        x_scale: Scale::Linear,
        y_scale: Scale::Log10,
        series: kinds
            .iter()
            .zip(CATEGORICAL)
            .map(|((kind, label), color)| Series {
                label: label.to_string(),
                points: rows
                    .iter()
                    .filter(|r| r.state == state.label() && r.miner_kind == *kind)
                    .map(|r| (r.attacker_fraction, r.log10_probability))
                    .collect(),
                color,
                markers: true,
            })
            .collect(),
        references: Vec::new(),
        legend: SeriesLabelPosition::LowerRight,
        y_range: None,
    };
    let both = [
        ("registered", "registered quorum (7 + 21)"),
        ("unregistered", "unregistered quorum (27 of 40)"),
    ];
    Figure {
        title: "Chance that the attacker controls a 40-node KWC".to_string(),
        subtitle: "Exact hypergeometric probabilities at 100,000 KWCs; seats assigned uniformly at random.".to_string(),
        panels: vec![
            panel(KwcState::Block, "(i) can block", &both),
            panel(KwcState::Sign, "(ii) can sign without honest members", &both),
            panel(KwcState::AllSeats, "(iii) holds every seat", &[("registered", "both quorums")]),
        ],
        size: (1800, 640),
    }
}

fn kwc_compositions(results: &M1Results) -> Figure {
    let rows: Vec<_> = results
        .b
        .compositions
        .iter()
        .filter(|r| r.initial_kwcs == 100_000 && r.ban_replacement_rate_per_year == 0.0)
        .collect();
    let series = [
        ("registered", "registered quorum (7 + 21)"),
        (
            "unregistered",
            "unregistered quorum (27 of 40), used by PoW-ID",
        ),
    ]
    .iter()
    .zip(CATEGORICAL)
    .map(|((kind, label), color)| Series {
        label: label.to_string(),
        points: log10_points(
            rows.iter()
                .filter(|r| r.miner_kind == *kind)
                .map(|r| (r.attacker_fraction, r.expected_sign_capable)),
        ),
        color,
        markers: true,
    })
    .collect();
    let horizon = rows.first().map(|r| r.horizon_years).unwrap_or(10.0);
    Figure {
        title: format!("Expected sign-capable KWC compositions over {} years", compact_number(horizon)),
        subtitle: "SPEC §10 H6 refresh model: 100,000 KWCs at the start, one new KWC per 10 new IDs, no bans; every composition counted as an independent draw.".to_string(),
        panels: vec![Panel {
            title: "Expected compositions in state (ii) (log scale)".to_string(),
            x_label: "attacker fraction of registered IDs, p".to_string(),
            y_label: "expected compositions".to_string(),
            x_scale: Scale::Linear,
            y_scale: Scale::Log10,
            series,
            references: vec![Reference {
                label: "1 expected".to_string(),
                value: 0.0,
            }],
            legend: SeriesLabelPosition::LowerRight,
            y_range: None,
        }],
        size: (1200, 760),
    }
}

fn cac_probabilities(results: &M1Results) -> Figure {
    let rows: Vec<_> = results
        .c
        .odds
        .iter()
        .filter(|r| r.mining_population.is_some() && r.honest_mining_fraction == 1.0)
        .collect();
    let sizes = distinct(rows.iter().map(|r| r.committee_size as f64));
    let colors = ramp(sizes.len());
    let panel = |title: &str, capture: bool| Panel {
        title: title.to_string(),
        x_label: "attacker fraction of mining IDs, p".to_string(),
        y_label: "probability (log scale)".to_string(),
        x_scale: Scale::Linear,
        y_scale: Scale::Log10,
        series: sizes
            .iter()
            .zip(colors.iter().cycle())
            .map(|(n, color)| Series {
                label: format!("n = {}", compact_number(*n)),
                points: rows
                    .iter()
                    .filter(|r| r.committee_size as f64 == *n)
                    .map(|r| {
                        let y = if capture {
                            r.log10_p_capture
                        } else {
                            r.log10_p_stall
                        };
                        (r.attacker_fraction, y)
                    })
                    .collect(),
                color: *color,
                markers: true,
            })
            .collect(),
        references: Vec::new(),
        legend: SeriesLabelPosition::LowerRight,
        y_range: None,
    };
    Figure {
        title: "Chain Allocation Committee: chance of stalling or capture".to_string(),
        subtitle: "Exact, one seat per ID, all IDs mining (2.1M). Stall: ≥ n − ⌈2n/3⌉ + 1 seats. Capture: ≥ ⌈2n/3⌉ seats.".to_string(),
        panels: vec![panel("Attacker can stall", false), panel("Attacker holds two-thirds", true)],
        size: (1700, 680),
    }
}

fn restart_advantage(results: &M1Results) -> Figure {
    let rows = &results.d_curve;
    let miners = distinct(rows.iter().map(|r| r.competing_miners as f64));
    let costs = distinct(rows.iter().map(|r| r.restart_cost_s));
    let colors = ramp(costs.len());
    let panels = miners
        .iter()
        .map(|n| Panel {
            title: format!("N = {} competing miners", short_count(*n as u64)),
            x_label: "keep window W (hours, log scale)".to_string(),
            y_label: "advantage over an honest miner".to_string(),
            x_scale: Scale::Log10,
            y_scale: Scale::Linear,
            series: costs
                .iter()
                .zip(colors.iter().cycle())
                .map(|(c, color)| Series {
                    label: format!("restart cost C = {} s", compact_number(*c)),
                    points: rows
                        .iter()
                        .filter(|r| r.competing_miners as f64 == *n && r.restart_cost_s == *c)
                        .map(|r| {
                            (
                                libm::log10(r.keep_window_s as f64 / 3_600.0),
                                r.advantage_old_design,
                            )
                        })
                        .collect(),
                    color: *color,
                    markers: false,
                })
                .collect(),
            references: vec![Reference {
                label: "per-round = 1".to_string(),
                value: 1.0,
            }],
            legend: SeriesLabelPosition::UpperLeft,
            y_range: None,
        })
        .collect();
    Figure {
        title: "Restart attack under the old design (entropy fixed for the whole connection)".to_string(),
        subtitle: "Advantage = honest expected time ÷ restarting miner's expected time. With per-round entropy the advantage is exactly 1.".to_string(),
        panels,
        size: (1700, 680),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_ticks_show_plain_numbers_near_one_and_powers_elsewhere() {
        assert_eq!(tick_label(0.0, Scale::Log10), "1");
        assert_eq!(tick_label(3.0, Scale::Log10), "1,000");
        assert_eq!(tick_label(-2.0, Scale::Log10), "0.01");
        assert_eq!(tick_label(-12.0, Scale::Log10), "10⁻¹²");
        assert_eq!(tick_label(-2.5, Scale::Log10), "");
    }

    #[test]
    fn linear_ticks_are_compact() {
        assert_eq!(tick_label(0.5, Scale::Linear), "0.5");
        assert_eq!(tick_label(2_100_000.0, Scale::Linear), "2,100,000");
        assert_eq!(compact_number(-0.0001), "0");
        assert_eq!(short_count(2_100_000), "2.1M");
        assert_eq!(short_count(100_000), "100k");
        assert_eq!(superscript(-400), "⁻⁴⁰⁰");
    }

    #[test]
    fn ramps_never_exceed_five_validated_steps() {
        assert_eq!(ramp(5).len(), 5);
        assert_eq!(ramp(9).len(), 5);
        assert_eq!(ramp(2).len(), 2);
    }

    #[test]
    fn pick_prefers_wanted_values_and_falls_back_to_even_spacing() {
        let values = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
        assert_eq!(
            pick(&values, &[0.5, 0.7, 0.9, 1.0], 4),
            vec![0.5, 0.7, 0.9, 1.0]
        );
        assert_eq!(pick(&values, &[0.33], 3), vec![0.5, 0.8, 1.0]);
    }

    #[test]
    fn a_small_figure_renders_to_png() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.png");
        let figure = Figure {
            title: "Test".to_string(),
            subtitle: "subtitle".to_string(),
            panels: vec![Panel {
                title: "panel".to_string(),
                x_label: "x".to_string(),
                y_label: "y".to_string(),
                x_scale: Scale::Linear,
                y_scale: Scale::Log10,
                series: vec![
                    Series {
                        label: "a".to_string(),
                        points: vec![(0.0, -3.0), (1.0, -1.0)],
                        color: CATEGORICAL[0],
                        markers: true,
                    },
                    Series {
                        label: "b".to_string(),
                        points: vec![(0.0, -2.0), (1.0, 0.0)],
                        color: CATEGORICAL[1],
                        markers: false,
                    },
                ],
                references: vec![Reference {
                    label: "ref".to_string(),
                    value: -1.5,
                }],
                legend: SeriesLabelPosition::LowerRight,
                y_range: None,
            }],
            size: (400, 300),
        };
        draw_figure(&path, &figure).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    }
}
