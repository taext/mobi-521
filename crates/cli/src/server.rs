use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use mobi521_core::{self as core, armor, keys::{encode_public_key, encode_secret_key, KeyPair}};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

// ─── Request/Response types ─────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct KeygenResponse {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "privateKey")]
    private_key: String,
}

#[derive(Deserialize)]
struct EncryptRequest {
    recipient: String,
    plaintext: String,
}

#[derive(Serialize)]
struct EncryptResponse {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptRequest {
    #[serde(rename = "privateKey")]
    private_key: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct DecryptResponse {
    plaintext: String,
}

#[derive(Deserialize)]
struct SignRequest {
    #[serde(rename = "privateKey")]
    private_key: String,
    message: String,
}

#[derive(Serialize)]
struct SignResponse {
    signature: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    #[serde(rename = "publicKey")]
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ─── Handlers ───────────────────────────────────────────────────────────────

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn keygen() -> Json<KeygenResponse> {
    let kp = KeyPair::generate();
    Json(KeygenResponse {
        public_key: encode_public_key(&kp.public),
        private_key: encode_secret_key(&kp.secret),
    })
}

async fn encrypt(Json(req): Json<EncryptRequest>) -> Result<Json<EncryptResponse>, impl IntoResponse> {
    let plaintext_bytes = req.plaintext.as_bytes();

    match core::encrypt(&req.recipient, plaintext_bytes) {
        Ok(ciphertext_bytes) => {
            // Return ASCII-armored for safe JSON transport
            let ciphertext = armor::armor(&ciphertext_bytes);
            Ok(Json(EncryptResponse { ciphertext }))
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e.to_string() }),
        )),
    }
}

async fn decrypt(Json(req): Json<DecryptRequest>) -> Result<Json<DecryptResponse>, impl IntoResponse> {
    let ciphertext_bytes = req.ciphertext.as_bytes();

    match core::decrypt(&req.private_key, ciphertext_bytes) {
        Ok(plaintext_bytes) => {
            match String::from_utf8(plaintext_bytes) {
                Ok(plaintext) => Ok(Json(DecryptResponse { plaintext })),
                Err(e) => Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { error: format!("Invalid UTF-8 in plaintext: {}", e) }),
                )),
            }
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e.to_string() }),
        )),
    }
}

async fn sign(Json(req): Json<SignRequest>) -> Result<Json<SignResponse>, impl IntoResponse> {
    let message_bytes = req.message.as_bytes();

    match core::sign(&req.private_key, message_bytes) {
        Ok(signature) => Ok(Json(SignResponse { signature })),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e.to_string() }),
        )),
    }
}

async fn verify(Json(req): Json<VerifyRequest>) -> Json<VerifyResponse> {
    let message_bytes = req.message.as_bytes();
    let valid = core::verify(&req.public_key, message_bytes, &req.signature).is_ok();
    Json(VerifyResponse { valid })
}

// ─── Router & Server ────────────────────────────────────────────────────────

pub fn create_router() -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/keygen", post(keygen))
        .route("/api/encrypt", post(encrypt))
        .route("/api/decrypt", post(decrypt))
        .route("/api/sign", post(sign))
        .route("/api/verify", post(verify))
}

pub async fn run_server(
    bind: &str,
    port: u16,
    tls: Option<(PathBuf, PathBuf)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    let router = create_router();

    let protocol = if tls.is_some() { "https" } else { "http" };
    eprintln!("mobi-521 API server listening on {}://{}", protocol, addr);
    eprintln!("Endpoints:");
    eprintln!("  GET  /api/health  - Health check");
    eprintln!("  POST /api/keygen  - Generate keypair");
    eprintln!("  POST /api/encrypt - Encrypt plaintext");
    eprintln!("  POST /api/decrypt - Decrypt ciphertext");
    eprintln!("  POST /api/sign    - Sign message");
    eprintln!("  POST /api/verify  - Verify signature");

    if let Some((cert_path, key_path)) = tls {
        let config = RustlsConfig::from_pem_file(&cert_path, &key_path).await?;
        axum_server::bind_rustls(addr, config)
            .serve(router.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router).await?;
    }

    Ok(())
}
