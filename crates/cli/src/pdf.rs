use qrcode::QrCode;
use std::path::PathBuf;

#[cfg(feature = "pdf")]
use printpdf::*;

/// Generate a key card PDF - A4 portrait with 2 IDENTICAL bifold cards (top/bottom)
///
/// Layout:
/// - A4 portrait (210×297mm)
/// - 2 landscape bifold cards stacked vertically
/// - Each card: 210×148.5mm with fold at x=105mm
/// - Top card: same keypair
/// - Bottom card: same keypair (duplicate for backup/sharing)
/// - Stippled cut line between cards
#[cfg(feature = "pdf")]
pub fn generate_key_card_pdf(
    pub_key: &str,
    sec_key: &str,
    output_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    generate_key_card_pdf_internal(
        pub_key, sec_key,
        Some((pub_key, sec_key)),
        output_path,
        true, // show cut line
    )
}

/// Generate a key card PDF - A4 portrait with SINGLE bifold card
#[cfg(feature = "pdf")]
pub fn generate_key_card_pdf_single(
    pub_key: &str,
    sec_key: &str,
    output_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    generate_key_card_pdf_internal(
        pub_key, sec_key,
        None, // no second card
        output_path,
        false, // no cut line
    )
}

/// Generate a key card PDF - A4 portrait with 2 DIFFERENT bifold cards
#[cfg(feature = "pdf")]
pub fn generate_key_card_pdf_dual(
    pub_key1: &str,
    sec_key1: &str,
    pub_key2: &str,
    sec_key2: &str,
    output_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    generate_key_card_pdf_internal(
        pub_key1, sec_key1,
        Some((pub_key2, sec_key2)),
        output_path,
        true, // show cut line
    )
}

/// Internal PDF generation function
#[cfg(feature = "pdf")]
fn generate_key_card_pdf_internal(
    pub_key1: &str,
    sec_key1: &str,
    second_card: Option<(&str, &str)>, // (pub_key2, sec_key2)
    output_path: &PathBuf,
    show_cut_line: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // A4 portrait dimensions
    let width_mm = 210.0;
    let height_mm = 297.0;
    let width_pt = Mm(width_mm);
    let height_pt = Mm(height_mm);

    // Card dimensions
    let card_height = 148.5; // Half of A4 height
    let fold_x = 105.0; // Vertical fold line (half of width)
    let panel_width = fold_x;

    // Create PDF document
    let (doc, page1, layer1) = PdfDocument::new(
        "mobi-521 Key Card - A4 Portrait (2 cards)",
        width_pt,
        height_pt,
        "Layer 1",
    );

    let current_layer = doc.get_page(page1).get_layer(layer1);

    // Fonts
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_mono = doc.add_builtin_font(BuiltinFont::Courier)?;

    // Generate QR codes for first card
    let pub_qr1 = QrCode::new(pub_key1)?;
    let sec_qr1 = QrCode::new(sec_key1)?;

    // Draw first card (top)
    draw_single_card(
        &current_layer,
        &font_bold,
        &font_regular,
        &font_mono,
        &pub_qr1,
        &sec_qr1,
        pub_key1,
        sec_key1,
        card_height, // Top card offset
        panel_width,
        card_height,
        fold_x,
    )?;

    // Draw second card if requested (bottom)
    if let Some((pub_key2, sec_key2)) = second_card {
        let pub_qr2 = QrCode::new(pub_key2)?;
        let sec_qr2 = QrCode::new(sec_key2)?;

        draw_single_card(
            &current_layer,
            &font_bold,
            &font_regular,
            &font_mono,
            &pub_qr2,
            &sec_qr2,
            pub_key2,
            sec_key2,
            0.0, // Bottom card offset
            panel_width,
            card_height,
            fold_x,
        )?;
    }

    // Draw stippled cut line between cards (only if there are two cards)
    if show_cut_line {
        draw_stippled_cut_line(&current_layer, Mm(0.0), Mm(card_height), Mm(width_mm));
    }

    // Save PDF
    doc.save(&mut std::io::BufWriter::new(std::fs::File::create(output_path)?))?;

    let card_count_msg = if second_card.is_some() { "2 cards" } else { "1 card" };
    eprintln!("Key card PDF (A4 portrait, {}) saved to: {}", card_count_msg, output_path.display());
    Ok(())
}

/// Draw a single bifold card
#[cfg(feature = "pdf")]
fn draw_single_card(
    layer: &PdfLayerReference,
    font_bold: &IndirectFontRef,
    font_regular: &IndirectFontRef,
    font_mono: &IndirectFontRef,
    pub_qr: &QrCode,
    sec_qr: &QrCode,
    pub_key: &str,
    sec_key: &str,
    offset_y: f32,
    panel_width: f32,
    card_height: f32,
    fold_x: f32,
) -> Result<(), Box<dyn std::error::Error>> {
    // Spacing (scaled down from original A4 landscape design)
    let top_offset = 12.0;
    let safe_margin = 8.0;

    // === LEFT PANEL: PUBLIC KEY ===
    let left_center_x = panel_width / 2.0;

    // Title "PUBLIC KEY"
    let title_y = offset_y + card_height - top_offset - 5.0;
    layer.use_text(
        "PUBLIC KEY",
        11.0,
        Mm(left_center_x - 16.0),
        Mm(title_y),
        font_bold,
    );

    // Divider line under title
    let divider_y = title_y - 5.0;
    let divider_width = 60.0;
    draw_horizontal_line(
        layer,
        Mm(left_center_x - divider_width / 2.0),
        Mm(divider_y),
        Mm(divider_width),
        0.4,
        [0.85, 0.85, 0.85],
    );

    // Public key text (monospace, centered, split into lines)
    let key_y_start = divider_y - 8.0;
    let key_lines = split_key_for_display(pub_key, 25);
    for (i, line) in key_lines.iter().enumerate() {
        let line_y = key_y_start - (i as f32 * 3.5);
        let text_width_approx = line.len() as f32 * 2.2;
        layer.use_text(
            line,
            7.5,
            Mm(left_center_x - text_width_approx / 2.0),
            Mm(line_y),
            font_mono,
        );
    }

    // QR code (public key) - green
    let qr_size_mm = 30.0;
    let qr_y = key_y_start - (key_lines.len() as f32 * 3.5) - 10.0;
    draw_qr_code(
        layer,
        pub_qr,
        Mm(left_center_x - qr_size_mm / 2.0),
        Mm(qr_y - qr_size_mm),
        Mm(qr_size_mm),
        [0.12, 0.48, 0.23], // Green #1F7A3A
    )?;

    // QR label "SCAN & SHARE"
    let qr_label_y = qr_y - qr_size_mm - 5.0;
    layer.set_fill_color(Color::Rgb(Rgb::new(0.12, 0.48, 0.23, None)));
    layer.use_text(
        "SCAN & SHARE",
        8.5,
        Mm(left_center_x - 16.0),
        Mm(qr_label_y),
        font_bold,
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None))); // Reset to black

    // === RIGHT PANEL: PRIVATE KEY ===
    let right_center_x = fold_x + panel_width / 2.0;

    // Title "PRIVATE KEY"
    layer.use_text(
        "PRIVATE KEY",
        11.0,
        Mm(right_center_x - 19.0),
        Mm(title_y),
        font_bold,
    );

    // Divider line under title
    draw_horizontal_line(
        layer,
        Mm(right_center_x - divider_width / 2.0),
        Mm(divider_y),
        Mm(divider_width),
        0.4,
        [0.85, 0.85, 0.85],
    );

    // Private key text (monospace, centered, split into lines)
    let sec_key_lines = split_key_for_display(sec_key, 25);
    for (i, line) in sec_key_lines.iter().enumerate() {
        let line_y = key_y_start - (i as f32 * 3.5);
        let text_width_approx = line.len() as f32 * 2.2;
        layer.use_text(
            line,
            7.5,
            Mm(right_center_x - text_width_approx / 2.0),
            Mm(line_y),
            font_mono,
        );
    }

    // QR code (private key) - red
    draw_qr_code(
        layer,
        sec_qr,
        Mm(right_center_x - qr_size_mm / 2.0),
        Mm(qr_y - qr_size_mm),
        Mm(qr_size_mm),
        [0.78, 0.16, 0.16], // Red #C62828
    )?;

    // QR label "KEEP SECURE"
    layer.set_fill_color(Color::Rgb(Rgb::new(0.78, 0.16, 0.16, None)));
    layer.use_text(
        "KEEP SECURE",
        8.5,
        Mm(right_center_x - 16.0),
        Mm(qr_label_y),
        font_bold,
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None))); // Reset to black

    // Meta data (bottom right corner)
    let meta_x = 210.0 - safe_margin - 3.0;
    let meta_y = offset_y + safe_margin + 5.0;

    // Meta divider line
    let meta_divider_width = 45.0;
    draw_horizontal_line(
        layer,
        Mm(meta_x - meta_divider_width),
        Mm(meta_y + 10.0),
        Mm(meta_divider_width),
        0.4,
        [0.85, 0.85, 0.85],
    );

    // Meta text
    let date = chrono::Local::now().format("%d %B %Y").to_string();
    layer.use_text(
        &format!("DATE: {}", date),
        7.5,
        Mm(meta_x - 40.0),
        Mm(meta_y + 6.0),
        font_regular,
    );
    layer.use_text(
        "KEY NAME: _____________________",
        7.5,
        Mm(meta_x - 40.0),
        Mm(meta_y),
        font_regular,
    );

    // Draw fold line (very light)
    draw_vertical_fold_line(layer, Mm(fold_x), Mm(offset_y), Mm(offset_y + card_height));

    Ok(())
}

/// Draw mailbox/mail slot icon (for public key - receive encrypted messages)
/// Represents: "Send encrypted messages to me here"
#[cfg(feature = "pdf")]
fn draw_key_icon(
    layer: &PdfLayerReference,
    center_x: Mm,
    center_y: Mm,
) -> Result<(), Box<dyn std::error::Error>> {
    use printpdf::{Line, Point, Rect};

    layer.set_outline_color(Color::Greyscale(Greyscale::new(0.1, None)));
    layer.set_outline_thickness(1.2);

    // Mailbox body (rectangle)
    let box_width = 5.0;
    let box_height = 4.0;
    let mailbox = Rect {
        ll: Point::new(Mm(center_x.0 - box_width / 2.0), Mm(center_y.0 - box_height / 2.0)),
        ur: Point::new(Mm(center_x.0 + box_width / 2.0), Mm(center_y.0 + box_height / 2.0)),
        mode: printpdf::path::PaintMode::Stroke,
        winding: printpdf::path::WindingOrder::NonZero,
    };
    layer.add_rect(mailbox);

    // Mail slot (horizontal line in upper part of box)
    let slot_width = 3.0;
    let slot_y = center_y.0 + 0.8;
    layer.add_line(Line {
        points: vec![
            (Point::new(Mm(center_x.0 - slot_width / 2.0), Mm(slot_y)), false),
            (Point::new(Mm(center_x.0 + slot_width / 2.0), Mm(slot_y)), false),
        ],
        is_closed: false,
    });

    // Envelope/letter being inserted (small rectangle above slot, slightly tilted)
    layer.set_outline_thickness(0.8);
    let envelope_width = 2.0;
    let envelope_height = 1.2;
    let envelope_y = center_y.0 + 2.0;

    // Simple envelope shape (rectangle)
    let envelope = Rect {
        ll: Point::new(Mm(center_x.0 - envelope_width / 2.0), Mm(envelope_y - envelope_height / 2.0)),
        ur: Point::new(Mm(center_x.0 + envelope_width / 2.0), Mm(envelope_y + envelope_height / 2.0)),
        mode: printpdf::path::PaintMode::Stroke,
        winding: printpdf::path::WindingOrder::NonZero,
    };
    layer.add_rect(envelope);

    // Envelope flap (V-shape on top of envelope)
    layer.add_line(Line {
        points: vec![
            (Point::new(Mm(center_x.0 - envelope_width / 2.0), Mm(envelope_y + envelope_height / 2.0)), false),
            (Point::new(Mm(center_x.0), Mm(envelope_y - envelope_height / 4.0)), false),
            (Point::new(Mm(center_x.0 + envelope_width / 2.0), Mm(envelope_y + envelope_height / 2.0)), false),
        ],
        is_closed: false,
    });

    Ok(())
}

/// Draw a simple lock icon
#[cfg(feature = "pdf")]
fn draw_lock_icon(
    layer: &PdfLayerReference,
    center_x: Mm,
    center_y: Mm,
) -> Result<(), Box<dyn std::error::Error>> {
    use printpdf::{Line, Point, Rect};

    layer.set_outline_color(Color::Greyscale(Greyscale::new(0.1, None)));
    layer.set_outline_thickness(1.2);

    // Lock body (rectangle, scaled down)
    let body_width = 3.5;
    let body_height = 3.0;
    let body = Rect {
        ll: Point::new(Mm(center_x.0 - body_width / 2.0), Mm(center_y.0 - body_height / 2.0)),
        ur: Point::new(Mm(center_x.0 + body_width / 2.0), Mm(center_y.0 + body_height / 2.0)),
        mode: printpdf::path::PaintMode::Stroke,
        winding: printpdf::path::WindingOrder::NonZero,
    };
    layer.add_rect(body);

    // Lock shackle (arc/semicircle on top)
    let shackle_width = 2.5;
    let mut shackle_points = Vec::new();
    for i in 0..=8 {
        let angle = std::f32::consts::PI * (i as f32 / 8.0);
        let x = center_x.0 + (shackle_width / 2.0) * angle.cos();
        let y = center_y.0 + body_height / 2.0 + (shackle_width / 2.0) * angle.sin();
        shackle_points.push((Point::new(Mm(x), Mm(y)), i == 0));
    }
    let shackle = Line {
        points: shackle_points,
        is_closed: false,
    };
    layer.add_line(shackle);

    Ok(())
}

/// Draw horizontal line
#[cfg(feature = "pdf")]
fn draw_horizontal_line(
    layer: &PdfLayerReference,
    x: Mm,
    y: Mm,
    width: Mm,
    thickness: f32,
    color: [f32; 3],
) {
    use printpdf::{Line, Point};

    layer.set_outline_color(Color::Rgb(Rgb::new(color[0], color[1], color[2], None)));
    layer.set_outline_thickness(thickness);

    let line = Line {
        points: vec![
            (Point::new(x, y), false),
            (Point::new(Mm(x.0 + width.0), y), false),
        ],
        is_closed: false,
    };

    layer.add_line(line);
    layer.set_outline_color(Color::Greyscale(Greyscale::new(0.0, None))); // Reset to black
}

/// Draw vertical fold line (very light)
#[cfg(feature = "pdf")]
fn draw_vertical_fold_line(layer: &PdfLayerReference, x: Mm, y1: Mm, y2: Mm) {
    use printpdf::{Line, Point};

    layer.set_outline_color(Color::Greyscale(Greyscale::new(0.9, None))); // Very light gray
    layer.set_outline_thickness(0.25);

    let line = Line {
        points: vec![
            (Point::new(x, y1), false),
            (Point::new(x, y2), false),
        ],
        is_closed: false,
    };

    layer.add_line(line);
}

/// Draw stippled cut line between cards
#[cfg(feature = "pdf")]
fn draw_stippled_cut_line(layer: &PdfLayerReference, x1: Mm, y: Mm, width: Mm) {
    use printpdf::{Line, Point};

    layer.set_outline_color(Color::Greyscale(Greyscale::new(0.6, None))); // Medium gray
    layer.set_outline_thickness(0.5);

    // Draw dashed line with short segments
    let dash_length = 3.0;
    let gap_length = 2.0;
    let segment_length = dash_length + gap_length;
    let num_segments = (width.0 / segment_length) as i32;

    for i in 0..num_segments {
        let start_x = x1.0 + (i as f32 * segment_length);
        let end_x = start_x + dash_length;

        let dash = Line {
            points: vec![
                (Point::new(Mm(start_x), y), false),
                (Point::new(Mm(end_x.min(x1.0 + width.0)), y), false),
            ],
            is_closed: false,
        };
        layer.add_line(dash);
    }

    layer.set_outline_color(Color::Greyscale(Greyscale::new(0.0, None))); // Reset to black
}

/// Draw QR code directly as vector rectangles in PDF
#[cfg(feature = "pdf")]
fn draw_qr_code(
    layer: &PdfLayerReference,
    qr: &QrCode,
    x: Mm,
    y: Mm,
    size: Mm,
    color: [f32; 3], // RGB color 0.0-1.0
) -> Result<(), Box<dyn std::error::Error>> {
    use printpdf::{Rect, Color, Rgb};

    let module_count = qr.width() as f32;
    let module_size = size.0 / module_count;

    // Set fill color for QR modules
    layer.set_fill_color(Color::Rgb(Rgb::new(color[0], color[1], color[2], None)));

    // Draw each QR module as a rectangle
    for row in 0..qr.width() {
        for col in 0..qr.width() {
            if qr[(col, row)] == qrcode::Color::Dark {
                let rect_x = x.0 + (col as f32 * module_size);
                let rect_y = y.0 + (row as f32 * module_size);

                let rect = Rect {
                    ll: Point::new(Mm(rect_x), Mm(rect_y)),
                    ur: Point::new(Mm(rect_x + module_size), Mm(rect_y + module_size)),
                    mode: printpdf::path::PaintMode::Fill,
                    winding: printpdf::path::WindingOrder::NonZero,
                };

                layer.add_rect(rect);
            }
        }
    }

    // Reset fill color
    layer.set_fill_color(Color::Greyscale(Greyscale::new(0.0, None)));

    Ok(())
}

/// Split key string into multiple lines for display (centered text)
fn split_key_for_display(key: &str, chars_per_line: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let chars: Vec<char> = key.chars().collect();

    for chunk in chars.chunks(chars_per_line) {
        lines.push(chunk.iter().collect());
    }

    lines
}

/// Stub functions when pdf feature is disabled
#[cfg(not(feature = "pdf"))]
pub fn generate_key_card_pdf(
    _pub_key: &str,
    _sec_key: &str,
    _output_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("PDF generation requires the 'pdf' feature. Rebuild with: cargo build --features pdf".into())
}

#[cfg(not(feature = "pdf"))]
pub fn generate_key_card_pdf_single(
    _pub_key: &str,
    _sec_key: &str,
    _output_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("PDF generation requires the 'pdf' feature. Rebuild with: cargo build --features pdf".into())
}

#[cfg(not(feature = "pdf"))]
pub fn generate_key_card_pdf_dual(
    _pub_key1: &str,
    _sec_key1: &str,
    _pub_key2: &str,
    _sec_key2: &str,
    _output_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("PDF generation requires the 'pdf' feature. Rebuild with: cargo build --features pdf".into())
}
