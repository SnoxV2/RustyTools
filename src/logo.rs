//! The RustyTools logo, rendered to an RGBA buffer with anti-aliasing so the
//! exact same mark serves as both the window/dock icon and the in-app header
//! texture: an orange rounded tile, two faint "signal" rings, and a Zilla
//! Slab "R". No external asset pipeline — the glyph is rasterized from the
//! bundled Bold font with ab_glyph, everything else is drawn with SDFs.

use ab_glyph::{Font, FontRef, PxScale};

use crate::theme::{LOGO_INK, ORANGE};

const FONT_BOLD: &[u8] = include_bytes!("../assets/fonts/ZillaSlab-Bold.ttf");

/// Renders the logo into a `size`×`size` straight-alpha RGBA buffer.
pub fn render_rgba(size: u32) -> Vec<u8> {
    let s = size as f32;
    let mut buf = vec![0u8; (size * size * 4) as usize];

    let orange = [ORANGE.r(), ORANGE.g(), ORANGE.b()];
    let ink = [LOGO_INK.r(), LOGO_INK.g(), LOGO_INK.b()];

    // Rounded tile, slight margin so the dock icon isn't edge-to-edge.
    let margin = s * 0.04;
    let half = (s - 2.0 * margin) / 2.0;
    let center = s / 2.0;
    let radius = half * 0.46;

    // Two engraved signal rings (dark, faint) inside the tile.
    let ring_w = s * 0.025;
    let rings = [half * 0.82, half * 0.58];

    for y in 0..size {
        for x in 0..size {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;

            let tile_cov = coverage(-rounded_box_sdf(px - center, py - center, half, half, radius));
            if tile_cov <= 0.0 {
                continue;
            }
            blend(&mut buf, size, x, y, orange, tile_cov);

            let dist_c = ((px - center).powi(2) + (py - center).powi(2)).sqrt();
            for r in rings {
                let ring_cov = coverage(ring_w * 0.5 - (dist_c - r).abs());
                if ring_cov > 0.0 {
                    blend(&mut buf, size, x, y, ink, 0.16 * ring_cov * tile_cov);
                }
            }
        }
    }

    draw_r(&mut buf, size, center, ink);
    buf
}

/// Window/dock icon at a comfortable resolution.
pub fn icon() -> eframe::egui::IconData {
    let size = 256;
    eframe::egui::IconData { rgba: render_rgba(size), width: size, height: size }
}

fn draw_r(buf: &mut [u8], size: u32, center: f32, ink: [u8; 3]) {
    let font = match FontRef::try_from_slice(FONT_BOLD) {
        Ok(f) => f,
        Err(_) => return,
    };
    let scale = PxScale::from(size as f32 * 0.62);
    let glyph = font.glyph_id('R').with_scale(scale);
    let Some(outlined) = font.outline_glyph(glyph) else { return };
    let b = outlined.px_bounds();
    // Center the glyph's ink box on the tile.
    let off_x = center - (b.min.x + b.width() / 2.0);
    let off_y = center - (b.min.y + b.height() / 2.0);
    outlined.draw(|gx, gy, c| {
        if c <= 0.0 {
            return;
        }
        let xi = (b.min.x + gx as f32 + off_x).round() as i32;
        let yi = (b.min.y + gy as f32 + off_y).round() as i32;
        if xi >= 0 && yi >= 0 && (xi as u32) < size && (yi as u32) < size {
            blend(buf, size, xi as u32, yi as u32, ink, c);
        }
    });
}

/// Signed distance to a rounded box centered at the origin (negative inside).
fn rounded_box_sdf(px: f32, py: f32, half_w: f32, half_h: f32, r: f32) -> f32 {
    let qx = px.abs() - (half_w - r);
    let qy = py.abs() - (half_h - r);
    let outside = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt();
    outside + qx.max(qy).min(0.0) - r
}

/// 1px-wide linear anti-aliasing from a signed coverage value.
fn coverage(v: f32) -> f32 {
    (v + 0.5).clamp(0.0, 1.0)
}

/// Straight-alpha "over" compositing of `color` at `alpha` onto the buffer.
fn blend(buf: &mut [u8], size: u32, x: u32, y: u32, color: [u8; 3], alpha: f32) {
    let a = alpha.clamp(0.0, 1.0);
    if a <= 0.0 {
        return;
    }
    let idx = ((y * size + x) * 4) as usize;
    let dst_a = buf[idx + 3] as f32 / 255.0;
    let out_a = a + dst_a * (1.0 - a);
    if out_a <= 0.0 {
        return;
    }
    for c in 0..3 {
        let src = color[c] as f32;
        let dst = buf[idx + c] as f32;
        let out = (src * a + dst * dst_a * (1.0 - a)) / out_a;
        buf[idx + c] = out.round().clamp(0.0, 255.0) as u8;
    }
    buf[idx + 3] = (out_a * 255.0).round().clamp(0.0, 255.0) as u8;
}
