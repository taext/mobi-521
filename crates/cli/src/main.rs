use mobi521_core::keys::{encode_public_key, encode_secret_key, KeyPair};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
    process,
};
use arboard::Clipboard;

mod qr;
mod pdf;

#[derive(Parser)]
#[command(
    name = "mobi521",
    about = "P-521 ECC encryption (ECDH + ChaCha20-Poly1305)",
    version = concat!(env!("CARGO_PKG_VERSION"), "\n-------------\nby david.2100 @ signal 2026-02-26"),
    help_template = "{name} {version}\n{about}\n\n{usage-heading} {usage}\n\n{all-args}"
)]
struct Cli {
    /// Print version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    version: (),

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new P-521 key pair and print both keys
    Keygen {
        /// Write the identity (private key) to this file instead of stdout
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Display QR codes as ASCII art in the terminal
        #[arg(long)]
        qr: bool,

        /// Save QR codes as PNG images. Creates {PREFIX}_public.png and {PREFIX}_secret.png
        #[arg(long, value_name = "PREFIX", requires = "qr")]
        qr_png: Option<String>,

        /// Generate a printable key card PDF (A4 portrait with bifold cards)
        #[arg(long, value_name = "FILE")]
        card_pdf: Option<PathBuf>,

        /// Generate only a single card instead of two (use with --card-pdf)
        #[arg(long, requires = "card_pdf")]
        single_card: bool,

        /// Generate two cards with different keypairs (use with --card-pdf)
        #[arg(long, requires = "card_pdf", conflicts_with = "single_card")]
        dual_keys: bool,
    },

    /// Encrypt a file or stdin for a recipient
    Encrypt {
        /// Recipient's public key (mobi521...). If omitted, uses the key in
        /// ~/.config/mobi521/default-recipient (or $XDG_CONFIG_HOME/mobi521/default-recipient).
        #[arg(short = 'r', long, value_name = "PUBKEY")]
        recipient: Option<String>,

        /// Write ciphertext to FILE (default: stdout)
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output raw binary instead of ASCII-armored text
        #[arg(long)]
        no_armor: bool,

        /// Encrypt a string directly instead of reading from file/stdin
        #[arg(short = 'm', long, value_name = "TEXT", conflicts_with = "input")]
        message: Option<String>,

        /// Input file (default: stdin)
        #[arg(value_name = "FILE")]
        input: Option<PathBuf>,
    },

    /// Decrypt a file or stdin using an identity (private key)
    Decrypt {
        /// Identity file containing the private key (MOBI521-SECRET-KEY-...)
        /// or the raw bech32 key string
        #[arg(short = 'i', long, value_name = "FILE")]
        identity: String,

        /// Write plaintext to FILE (default: stdout)
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Input file (default: stdin)
        #[arg(value_name = "FILE")]
        input: Option<PathBuf>,
    },

    /// Sign a file or stdin with an identity (private key)
    Sign {
        /// Identity file or raw private key string
        #[arg(short = 'i', long, value_name = "IDENTITY")]
        identity: String,

        /// Write the base64 signature to FILE (default: stdout)
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Input file to sign (default: stdin)
        #[arg(value_name = "FILE")]
        input: Option<PathBuf>,
    },

    /// Verify a signature against a file or stdin
    Verify {
        /// Signer's public key (mobi521...)
        #[arg(short = 'p', long, value_name = "PUBKEY")]
        pubkey: String,

        /// Base64 signature string or path to a signature file
        #[arg(short = 's', long, value_name = "SIGNATURE")]
        signature: String,

        /// Input file that was signed (default: stdin)
        #[arg(value_name = "FILE")]
        input: Option<PathBuf>,
    },

    /// Export a printable key card PDF from an existing identity
    ExportPdf {
        /// Identity file or raw private key string
        #[arg(short = 'i', long, value_name = "IDENTITY")]
        identity: String,

        /// Output PDF file path
        #[arg(short = 'o', long, value_name = "FILE", default_value = "keycard.pdf")]
        output: PathBuf,

        /// Generate only a single card instead of two
        #[arg(long)]
        single_card: bool,

        /// Generate two cards with different keypairs (generates a second random keypair)
        #[arg(long, conflicts_with = "single_card")]
        dual_keys: bool,
    },

    /// Generate shell completion scripts
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            Cli::command().print_help()?;
            return Ok(());
        }
    };

    match command {
        Command::Keygen { output, qr, qr_png, card_pdf, single_card, dual_keys } => {
            let kp = KeyPair::generate();
            let pub_str = encode_public_key(&kp.public);
            let sec_str = encode_secret_key(&kp.secret);

            let content = format!(
                "# created: mobi521 keygen\n# public key: {}\n{}\n",
                pub_str, sec_str
            );

            match output {
                Some(path) => {
                    fs::write(&path, &content)?;
                    eprintln!("Public key:  {}", pub_str);
                    eprintln!("Identity written to: {}", path.display());
                }
                None => {
                    println!("{}", content.trim());
                }
            }

            // Generate QR codes if requested
            if qr || qr_png.is_some() {
                qr::generate_keygen_qrs(&pub_str, &sec_str, qr, qr_png.as_deref())?;
            }

            // Generate key card PDF if requested
            if let Some(pdf_path) = card_pdf {
                if single_card {
                    // Generate single card
                    pdf::generate_key_card_pdf_single(&pub_str, &sec_str, &pdf_path)?;
                } else if dual_keys {
                    // Generate two cards with different keypairs
                    let kp2 = KeyPair::generate();
                    let pub_str2 = encode_public_key(&kp2.public);
                    let sec_str2 = encode_secret_key(&kp2.secret);

                    // Print second keypair to stderr
                    eprintln!("\nSecond keypair generated:");
                    eprintln!("Public key:  {}", pub_str2);
                    eprintln!("Secret key:  {}", sec_str2);

                    pdf::generate_key_card_pdf_dual(
                        &pub_str, &sec_str,
                        &pub_str2, &sec_str2,
                        &pdf_path
                    )?;
                } else {
                    // Default: two identical cards
                    pdf::generate_key_card_pdf(&pub_str, &sec_str, &pdf_path)?;
                }
            }
        }

        Command::Encrypt {
            recipient,
            output,
            no_armor,
            message,
            input,
        } => {
            let pubkey = match recipient {
                Some(r) => r,
                None => default_recipient()?,
            };
            // Determine plaintext source: --message flag, input file, or clipboard/stdin
            let (plaintext, use_clipboard) = if let Some(msg) = message {
                (msg.into_bytes(), false)
            } else {
                // Only use clipboard if no input file AND stdin is a TTY (not piped)
                let use_clip = input.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdin());
                (read_input(input)?, use_clip)
            };
            let ciphertext = mobi521_core::encrypt(&pubkey, &plaintext)?;
            if no_armor {
                write_output(output, &ciphertext, use_clipboard)?;
            } else {
                let armored = mobi521_core::armor::armor(&ciphertext);
                write_output(output, armored.as_bytes(), use_clipboard)?;
            }
        }

        Command::Decrypt {
            identity,
            output,
            input,
        } => {
            // Accept either a path to a key file, or the raw key string
            let secret_key = resolve_identity(&identity)?;
            // Only use clipboard if no input file AND stdin is a TTY (not piped)
            let use_clipboard = input.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdin());
            let ciphertext = read_input(input)?;
            let plaintext = mobi521_core::decrypt(&secret_key, &ciphertext)?;
            write_output(output, &plaintext, use_clipboard)?;
        }

        Command::Sign {
            identity,
            output,
            input,
        } => {
            let secret_key = resolve_identity(&identity)?;
            // Only use clipboard if no input file AND stdin is a TTY (not piped)
            let use_clipboard = input.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdin());
            let message = read_input(input)?;
            let sig = mobi521_core::sign(&secret_key, &message)?;
            let to_stdout = output.is_none() && !use_clipboard;
            write_output(output, sig.as_bytes(), use_clipboard)?;
            if to_stdout {
                io::stdout().write_all(b"\n")?;
            }
        }

        Command::Verify {
            pubkey,
            signature,
            input,
        } => {
            let message = read_input(input)?;
            // Accept either a path to a signature file or a raw base64 string
            let sig_b64 = resolve_sig(&signature)?;
            match mobi521_core::verify(&pubkey, &message, &sig_b64) {
                Ok(()) => {
                    eprintln!("Signature valid.");
                }
                Err(e) => {
                    eprintln!("Signature INVALID: {}", e);
                    process::exit(1);
                }
            }
        }

        Command::ExportPdf {
            identity,
            output,
            single_card,
            dual_keys,
        } => {
            use mobi521_core::keys::{decode_secret_key, encode_public_key, encode_secret_key, KeyPair};

            // Resolve identity (file path or raw key string)
            let sec_str = resolve_identity(&identity)?;

            // Decode the secret key
            let secret_key = decode_secret_key(&sec_str)?;

            // Derive public key from secret key
            let public_key = secret_key.public_key();

            // Encode both keys as bech32 strings
            let pub_str = encode_public_key(&public_key);
            let sec_str_encoded = encode_secret_key(&secret_key);

            // Generate PDF
            if single_card {
                pdf::generate_key_card_pdf_single(&pub_str, &sec_str_encoded, &output)?;
            } else if dual_keys {
                // Generate second keypair
                let kp2 = KeyPair::generate();
                let pub_str2 = encode_public_key(&kp2.public);
                let sec_str2 = encode_secret_key(&kp2.secret);

                // Print second keypair to stderr
                eprintln!("\nSecond keypair generated:");
                eprintln!("Public key:  {}", pub_str2);
                eprintln!("Secret key:  {}", sec_str2);

                pdf::generate_key_card_pdf_dual(
                    &pub_str, &sec_str_encoded,
                    &pub_str2, &sec_str2,
                    &output
                )?;
            } else {
                // Default: two identical cards
                pdf::generate_key_card_pdf(&pub_str, &sec_str_encoded, &output)?;
            }
        }

        Command::Completions { shell } => {
            if shell == Shell::Fish {
                // Use hand-written Fish completions (clap's generated ones don't work)
                print!("{}", FISH_COMPLETIONS);
            } else {
                let mut cmd = Cli::command();
                generate(shell, &mut cmd, "mobi521", &mut io::stdout());
            }
        }
    }

    Ok(())
}

/// Read all bytes from a file, clipboard, or stdin.
fn read_input(path: Option<PathBuf>) -> io::Result<Vec<u8>> {
    match path {
        Some(p) => fs::read(p),
        None => read_from_clipboard_or_stdin(),
    }
}

/// Write bytes to a file, clipboard (if no input file), or stdout.
/// use_clipboard: true if clipboard should be tried (when no input file was given)
fn write_output(path: Option<PathBuf>, data: &[u8], use_clipboard: bool) -> io::Result<()> {
    match path {
        Some(p) => fs::write(p, data),
        None => {
            if use_clipboard {
                write_to_clipboard_or_stdout(data)
            } else {
                io::stdout().write_all(data)
            }
        }
    }
}

/// Resolve a signature argument: either a path to a signature file or a raw base64 string.
fn resolve_sig(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = PathBuf::from(s);
    if path.exists() {
        let contents = fs::read_to_string(&path)?;
        Ok(contents.trim().to_string())
    } else {
        Ok(s.to_string())
    }
}

/// Return the default recipient public key from ~/.config/mobi521/default-recipient
/// (or $XDG_CONFIG_HOME/mobi521/default-recipient).
fn default_recipient() -> Result<String, Box<dyn std::error::Error>> {
    let config_dir = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("mobi521")
    } else {
        let home = std::env::var("HOME")
            .map_err(|_| "HOME environment variable not set")?;
        PathBuf::from(home).join(".config").join("mobi521")
    };
    let path = config_dir.join("default-recipient");
    if !path.exists() {
        return Err(format!(
            "no --recipient given and no default recipient found\n\
             hint: put your public key in {}",
            path.display()
        )
        .into());
    }
    let contents = fs::read_to_string(&path)?;
    let key = contents.trim().to_string();
    if key.is_empty() {
        return Err(format!("default-recipient file is empty: {}", path.display()).into());
    }
    Ok(key)
}

/// Resolve an identity argument: either a path to a key file or a raw key string.
fn resolve_identity(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = PathBuf::from(s);
    if path.exists() {
        // Read the file and extract the first non-comment, non-empty line
        let contents = fs::read_to_string(&path)?;
        for line in contents.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                return Ok(line.to_string());
            }
        }
        Err(format!("no key found in identity file '{}'", s).into())
    } else {
        // Treat as a raw key string
        Ok(s.to_string())
    }
}

/// Try to read from clipboard using wl-paste (Wayland).
fn try_wl_paste() -> io::Result<Vec<u8>> {
    match process::Command::new("wl-paste").output() {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => {
            eprintln!("reading from clipboard via wl-paste ({} bytes)", output.stdout.len());
            Ok(output.stdout)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            "wl-paste failed or clipboard empty",
        )),
    }
}

/// Try to read from clipboard, fall back to stdin if clipboard unavailable.
/// If stdin is not a TTY (i.e., data is being piped), read from stdin directly.
fn read_from_clipboard_or_stdin() -> io::Result<Vec<u8>> {
    // If stdin is not a TTY, data is being piped — read from stdin directly
    if !std::io::IsTerminal::is_terminal(&io::stdin()) {
        return read_from_stdin();
    }

    // stdin is a TTY, try clipboard first
    match Clipboard::new() {
        Ok(mut clipboard) => {
            match clipboard.get_text() {
                Ok(text) => {
                    if text.is_empty() {
                        // Try wl-paste on Wayland
                        if std::env::var("WAYLAND_DISPLAY").is_ok() {
                            if let Ok(data) = try_wl_paste() {
                                return Ok(data);
                            }
                        }
                        eprintln!("clipboard is empty, falling back to stdin");
                        read_from_stdin()
                    } else {
                        eprintln!("reading from clipboard ({} bytes)", text.len());
                        Ok(text.into_bytes())
                    }
                }
                Err(_) => {
                    // arboard failed, try wl-paste on Wayland
                    if std::env::var("WAYLAND_DISPLAY").is_ok() {
                        if let Ok(data) = try_wl_paste() {
                            return Ok(data);
                        }
                    }
                    eprintln!("clipboard doesn't contain text (may be image/binary data), falling back to stdin");
                    read_from_stdin()
                }
            }
        }
        Err(_) => {
            // arboard failed to initialize, try wl-paste on Wayland
            if std::env::var("WAYLAND_DISPLAY").is_ok() {
                if let Ok(data) = try_wl_paste() {
                    return Ok(data);
                }
            }
            eprintln!("failed to access clipboard, falling back to stdin");
            read_from_stdin()
        }
    }
}

/// Read from stdin.
fn read_from_stdin() -> io::Result<Vec<u8>> {
    if std::io::IsTerminal::is_terminal(&io::stdin()) {
        eprintln!("reading from stdin — paste input then press Ctrl+D");
    }
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

/// Try to write to clipboard using wl-copy (Wayland).
fn try_wl_copy(data: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let mut child = process::Command::new("wl-copy")
        .stdin(process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data)?;
    }

    let status = child.wait()?;
    if status.success() {
        eprintln!("written to clipboard via wl-copy");
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "wl-copy failed"))
    }
}

/// Try to write to clipboard, fall back to stdout if clipboard unavailable.
fn write_to_clipboard_or_stdout(data: &[u8]) -> io::Result<()> {
    // On Wayland, prefer wl-copy since arboard doesn't work reliably
    if std::env::var("WAYLAND_DISPLAY").is_ok() {
        if try_wl_copy(data).is_ok() {
            return Ok(());
        }
    }

    // Fall back to arboard (for X11, macOS, Windows)
    match Clipboard::new() {
        Ok(mut clipboard) => {
            // Convert bytes to string for clipboard
            match std::str::from_utf8(data) {
                Ok(text) => {
                    match clipboard.set_text(text) {
                        Ok(_) => {
                            eprintln!("written to clipboard");
                            Ok(())
                        }
                        Err(_) => {
                            eprintln!("clipboard write failed, falling back to stdout");
                            io::stdout().write_all(data)
                        }
                    }
                }
                Err(_) => {
                    eprintln!("output is not valid UTF-8, falling back to stdout");
                    io::stdout().write_all(data)
                }
            }
        }
        Err(_) => {
            eprintln!("clipboard unavailable, falling back to stdout");
            io::stdout().write_all(data)
        }
    }
}

/// Hand-written Fish completions (clap_complete's generated ones don't work with Fish 4.x)
const FISH_COMPLETIONS: &str = r#"# mobi521 completions for Fish shell
# Disable file completions by default
complete -c mobi521 -f

# Subcommands
complete -c mobi521 -n "__fish_use_subcommand" -a keygen -d "Generate a new P-521 key pair"
complete -c mobi521 -n "__fish_use_subcommand" -a encrypt -d "Encrypt a file or stdin"
complete -c mobi521 -n "__fish_use_subcommand" -a decrypt -d "Decrypt a file or stdin"
complete -c mobi521 -n "__fish_use_subcommand" -a sign -d "Sign a file or stdin"
complete -c mobi521 -n "__fish_use_subcommand" -a verify -d "Verify a signature"
complete -c mobi521 -n "__fish_use_subcommand" -a export-pdf -d "Export printable key card PDF"
complete -c mobi521 -n "__fish_use_subcommand" -a completions -d "Generate shell completions"
complete -c mobi521 -n "__fish_use_subcommand" -a help -d "Print help"
complete -c mobi521 -n "__fish_use_subcommand" -s v -l version -d "Print version"
complete -c mobi521 -n "__fish_use_subcommand" -s h -l help -d "Print help"

# keygen options
complete -c mobi521 -n "__fish_seen_subcommand_from keygen" -s o -l output -rF -d "Write identity to file"
complete -c mobi521 -n "__fish_seen_subcommand_from keygen" -l qr -d "Display QR codes in terminal"
complete -c mobi521 -n "__fish_seen_subcommand_from keygen" -l qr-png -r -d "Save QR codes as PNG"
complete -c mobi521 -n "__fish_seen_subcommand_from keygen" -l card-pdf -rF -d "Generate key card PDF"
complete -c mobi521 -n "__fish_seen_subcommand_from keygen" -l single-card -d "Generate single card"
complete -c mobi521 -n "__fish_seen_subcommand_from keygen" -l dual-keys -d "Generate two keypairs"
complete -c mobi521 -n "__fish_seen_subcommand_from keygen" -s h -l help -d "Print help"

# encrypt options
complete -c mobi521 -n "__fish_seen_subcommand_from encrypt" -s r -l recipient -r -d "Recipient's public key"
complete -c mobi521 -n "__fish_seen_subcommand_from encrypt" -s o -l output -rF -d "Write ciphertext to file"
complete -c mobi521 -n "__fish_seen_subcommand_from encrypt" -l no-armor -d "Output raw binary"
complete -c mobi521 -n "__fish_seen_subcommand_from encrypt" -s m -l message -r -d "Encrypt string directly"
complete -c mobi521 -n "__fish_seen_subcommand_from encrypt" -s h -l help -d "Print help"
complete -c mobi521 -n "__fish_seen_subcommand_from encrypt" -F -d "Input file"

# decrypt options
complete -c mobi521 -n "__fish_seen_subcommand_from decrypt" -s i -l identity -rF -d "Identity file or key"
complete -c mobi521 -n "__fish_seen_subcommand_from decrypt" -s o -l output -rF -d "Write plaintext to file"
complete -c mobi521 -n "__fish_seen_subcommand_from decrypt" -s h -l help -d "Print help"
complete -c mobi521 -n "__fish_seen_subcommand_from decrypt" -F -d "Input file"

# sign options
complete -c mobi521 -n "__fish_seen_subcommand_from sign" -s i -l identity -rF -d "Identity file or key"
complete -c mobi521 -n "__fish_seen_subcommand_from sign" -s o -l output -rF -d "Write signature to file"
complete -c mobi521 -n "__fish_seen_subcommand_from sign" -s h -l help -d "Print help"
complete -c mobi521 -n "__fish_seen_subcommand_from sign" -F -d "Input file"

# verify options
complete -c mobi521 -n "__fish_seen_subcommand_from verify" -s p -l pubkey -r -d "Signer's public key"
complete -c mobi521 -n "__fish_seen_subcommand_from verify" -s s -l signature -r -d "Signature string or file"
complete -c mobi521 -n "__fish_seen_subcommand_from verify" -s h -l help -d "Print help"
complete -c mobi521 -n "__fish_seen_subcommand_from verify" -F -d "Input file"

# export-pdf options
complete -c mobi521 -n "__fish_seen_subcommand_from export-pdf" -s i -l identity -rF -d "Identity file or key"
complete -c mobi521 -n "__fish_seen_subcommand_from export-pdf" -s o -l output -rF -d "Output PDF path"
complete -c mobi521 -n "__fish_seen_subcommand_from export-pdf" -l single-card -d "Generate single card"
complete -c mobi521 -n "__fish_seen_subcommand_from export-pdf" -l dual-keys -d "Generate two keypairs"
complete -c mobi521 -n "__fish_seen_subcommand_from export-pdf" -s h -l help -d "Print help"

# completions options
complete -c mobi521 -n "__fish_seen_subcommand_from completions" -a "bash zsh fish elvish powershell" -d "Shell type"
complete -c mobi521 -n "__fish_seen_subcommand_from completions" -s h -l help -d "Print help"

# help subcommand
complete -c mobi521 -n "__fish_seen_subcommand_from help" -a "keygen encrypt decrypt sign verify export-pdf completions" -d "Subcommand"
"#;
