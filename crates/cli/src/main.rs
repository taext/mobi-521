use mobi521_core::keys::{encode_public_key, encode_secret_key, KeyPair};
use clap::{Parser, Subcommand};
use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
    process,
};

#[derive(Parser)]
#[command(
    name = "mobi521",
    about = "P-521 ECC encryption (ECDH + ChaCha20-Poly1305)",
    version,
    help_template = "{name} {version}\n{about}\n\n{usage-heading} {usage}\n\n{all-args}"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new P-521 key pair and print both keys
    Keygen {
        /// Write the identity (private key) to this file instead of stdout
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Encrypt a file or stdin for a recipient
    Encrypt {
        /// Recipient's public key (mobi521...)
        #[arg(short = 'r', long, value_name = "PUBKEY")]
        recipient: String,

        /// Write ciphertext to FILE (default: stdout)
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output raw binary instead of ASCII-armored text
        #[arg(long)]
        no_armor: bool,

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
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Keygen { output } => {
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
                    eprintln!("# Public key: {}", pub_str);
                }
            }
        }

        Command::Encrypt {
            recipient,
            output,
            no_armor,
            input,
        } => {
            let plaintext = read_input(input)?;
            let ciphertext = mobi521_core::encrypt(&recipient, &plaintext)?;
            if no_armor {
                write_output(output, &ciphertext)?;
            } else {
                let armored = mobi521_core::armor::armor(&ciphertext);
                write_output(output, armored.as_bytes())?;
            }
        }

        Command::Decrypt {
            identity,
            output,
            input,
        } => {
            // Accept either a path to a key file, or the raw key string
            let secret_key = resolve_identity(&identity)?;
            let ciphertext = read_input(input)?;
            let plaintext = mobi521_core::decrypt(&secret_key, &ciphertext)?;
            write_output(output, &plaintext)?;
        }

        Command::Sign {
            identity,
            output,
            input,
        } => {
            let secret_key = resolve_identity(&identity)?;
            let message = read_input(input)?;
            let sig = mobi521_core::sign(&secret_key, &message)?;
            let to_stdout = output.is_none();
            write_output(output, sig.as_bytes())?;
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
    }

    Ok(())
}

/// Read all bytes from a file or stdin.
fn read_input(path: Option<PathBuf>) -> io::Result<Vec<u8>> {
    match path {
        Some(p) => fs::read(p),
        None => {
            if std::io::IsTerminal::is_terminal(&io::stdin()) {
                eprintln!("reading from stdin — paste input then press Ctrl+D");
            }
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

/// Write bytes to a file or stdout.
fn write_output(path: Option<PathBuf>, data: &[u8]) -> io::Result<()> {
    match path {
        Some(p) => fs::write(p, data),
        None => io::stdout().write_all(data),
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
