//! Single dark theme with Claude-orange accents, applied globally, plus the
//! bundled Zilla Slab fonts used for the logo, wordmark and headings.

use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, TextStyle};

// Warm near-black surfaces.
pub const BG_WINDOW: Color32 = Color32::from_rgb(0x1A, 0x19, 0x16);
pub const BG_SURFACE: Color32 = Color32::from_rgb(0x21, 0x1F, 0x1B);
pub const BG_WIDGET: Color32 = Color32::from_rgb(0x2A, 0x27, 0x23);
pub const BG_HOVER: Color32 = Color32::from_rgb(0x35, 0x31, 0x2B);
pub const BG_INPUT: Color32 = Color32::from_rgb(0x14, 0x13, 0x11);

// Claude orange and a darker pressed variant.
pub const ORANGE: Color32 = Color32::from_rgb(0xD9, 0x77, 0x57);
pub const ORANGE_PRESSED: Color32 = Color32::from_rgb(0xB5, 0x60, 0x3F);
pub const LOGO_INK: Color32 = Color32::from_rgb(0x1C, 0x1A, 0x17);

// Text.
pub const TEXT: Color32 = Color32::from_rgb(0xEC, 0xE7, 0xDE);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0xA8, 0xA2, 0x9A);
/// Deliberately dim, for placeholder/hint text drawn manually (egui's own
/// hint color is capped at a 50% blend and reads too much like a value).
pub const HINT: Color32 = Color32::from_rgb(0x63, 0x5F, 0x58);
pub const BORDER: Color32 = Color32::from_rgb(0x3A, 0x36, 0x30);

// Status colors tuned for the dark background.
pub const OK: Color32 = Color32::from_rgb(0x7B, 0xC4, 0x8A);
pub const WARN: Color32 = Color32::from_rgb(0xE7, 0xB4, 0x5A);
pub const DANGER: Color32 = Color32::from_rgb(0xE5, 0x73, 0x73);

pub const ZILLA: &str = "zilla";
pub const ZILLA_BOLD: &str = "zilla-bold";

/// Fonts + style + visuals, in that order (style references the families).
pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);
    install_style(ctx);
    ctx.set_visuals(visuals());
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        ZILLA.to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/fonts/ZillaSlab-SemiBold.ttf"))
            .into(),
    );
    fonts.font_data.insert(
        ZILLA_BOLD.to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/fonts/ZillaSlab-Bold.ttf")).into(),
    );
    fonts.families.insert(FontFamily::Name(ZILLA.into()), vec![ZILLA.to_owned()]);
    fonts.families.insert(FontFamily::Name(ZILLA_BOLD.into()), vec![ZILLA_BOLD.to_owned()]);
    ctx.set_fonts(fonts);
}

fn install_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(20.0, FontFamily::Name(ZILLA.into())),
    );
    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.button_padding = egui::vec2(9.0, 5.0);
    style.visuals.clip_rect_margin = 2.0;
    ctx.set_style(style);
}

fn rounding() -> CornerRadius {
    CornerRadius::same(6)
}

fn visuals() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    v.override_text_color = Some(TEXT);
    v.panel_fill = BG_WINDOW;
    v.window_fill = BG_WINDOW;
    v.window_stroke = egui::Stroke::new(1.0, BORDER);
    v.extreme_bg_color = BG_INPUT;
    v.faint_bg_color = BG_SURFACE;
    v.hyperlink_color = ORANGE;

    v.widgets.noninteractive.bg_fill = BG_SURFACE;
    v.widgets.noninteractive.weak_bg_fill = BG_SURFACE;
    v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT_MUTED);
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);

    v.widgets.inactive.bg_fill = BG_WIDGET;
    v.widgets.inactive.weak_bg_fill = BG_WIDGET;
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);

    v.widgets.hovered.bg_fill = BG_HOVER;
    v.widgets.hovered.weak_bg_fill = BG_HOVER;
    v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT);
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ORANGE);

    v.widgets.active.bg_fill = ORANGE_PRESSED;
    v.widgets.active.weak_bg_fill = ORANGE_PRESSED;
    v.widgets.active.fg_stroke = egui::Stroke::new(1.0, TEXT);
    v.widgets.active.bg_stroke = egui::Stroke::new(1.0, ORANGE);

    // Selected selectable_value / text selection use the accent.
    v.selection.bg_fill = ORANGE.gamma_multiply(0.40);
    v.selection.stroke = egui::Stroke::new(1.0, ORANGE);

    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = rounding();
    }
    v
}
