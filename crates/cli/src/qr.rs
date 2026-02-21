use qrcode::QrCode;

#[cfg(feature = "qr-png")]
use std::path::PathBuf;

/// Render QR code as ASCII art to terminal (stderr)
pub fn print_qr_ascii(label: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    use qrcode::render::unicode;

    let code = QrCode::new(data)?;
    let string = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .build();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("{}", label);
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("{}", string);

    Ok(())
}

/// Save QR code as PNG image
#[cfg(feature = "qr-png")]
pub fn save_qr_png(path: &PathBuf, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    use image::Luma;

    let code = QrCode::new(data)?;
    let img = code
        .render::<Luma<u8>>()
        .min_dimensions(200, 200)
        .build();
    img.save(path)?;

    Ok(())
}

/// Generate QR codes for both public and private keys
pub fn generate_keygen_qrs(
    pub_key: &str,
    sec_key: &str,
    display_ascii: bool,
    png_prefix: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Display ASCII QR codes if requested
    if display_ascii {
        print_qr_ascii("Public Key QR Code:", pub_key)?;
        print_qr_ascii("⚠️  Private Key QR Code (keep secret!):", sec_key)?;
        eprintln!("\n⚠️  WARNING: QR codes contain sensitive key material.");
        eprintln!("   Clear your terminal after use.\n");
    }

    // Save PNG QR codes if requested
    #[cfg(feature = "qr-png")]
    if let Some(prefix) = png_prefix {
        let pub_path = PathBuf::from(format!("{}_public.png", prefix));
        let sec_path = PathBuf::from(format!("{}_secret.png", prefix));

        save_qr_png(&pub_path, pub_key)?;
        save_qr_png(&sec_path, sec_key)?;

        eprintln!("QR codes saved:");
        eprintln!("  Public:  {}", pub_path.display());
        eprintln!("  Private: {}", sec_path.display());
    }

    #[cfg(not(feature = "qr-png"))]
    if png_prefix.is_some() {
        eprintln!("Warning: --qr-png requires the 'qr-png' feature.");
        eprintln!("Rebuild with: cargo build --features qr-png");
    }

    Ok(())
}
