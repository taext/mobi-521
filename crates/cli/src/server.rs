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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health() {
        let app = create_router();
        let response = app
            .oneshot(Request::builder().uri("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn test_keygen() {
        let app = create_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/keygen")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["publicKey"].as_str().unwrap().starts_with("mobi521"));
        assert!(json["privateKey"].as_str().unwrap().starts_with("MOBI521-SECRET-KEY"));
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let app = create_router();

        // Generate keypair
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/keygen")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let keys: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let pub_key = keys["publicKey"].as_str().unwrap();
        let priv_key = keys["privateKey"].as_str().unwrap();

        // Encrypt
        let plaintext = "Hello, mobi-521 API!";
        let encrypt_req = serde_json::json!({
            "recipient": pub_key,
            "plaintext": plaintext
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/encrypt")
                    .header("content-type", "application/json")
                    .body(Body::from(encrypt_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let enc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext = enc["ciphertext"].as_str().unwrap();
        assert!(ciphertext.contains("-----BEGIN MOBI-521 ENCRYPTED FILE-----"));

        // Decrypt
        let decrypt_req = serde_json::json!({
            "privateKey": priv_key,
            "ciphertext": ciphertext
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/decrypt")
                    .header("content-type", "application/json")
                    .body(Body::from(decrypt_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let dec: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(dec["plaintext"], plaintext);
    }

    #[tokio::test]
    async fn test_sign_verify_roundtrip() {
        let app = create_router();

        // Generate keypair
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/keygen")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let keys: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let pub_key = keys["publicKey"].as_str().unwrap();
        let priv_key = keys["privateKey"].as_str().unwrap();

        // Sign
        let message = "Sign this message";
        let sign_req = serde_json::json!({
            "privateKey": priv_key,
            "message": message
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(sign_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let sig: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let signature = sig["signature"].as_str().unwrap();

        // Verify (valid)
        let verify_req = serde_json::json!({
            "publicKey": pub_key,
            "message": message,
            "signature": signature
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(verify_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["valid"], true);

        // Verify (tampered message)
        let verify_req = serde_json::json!({
            "publicKey": pub_key,
            "message": "TAMPERED message",
            "signature": signature
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(verify_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["valid"], false);
    }

    #[tokio::test]
    async fn test_encrypt_invalid_key() {
        let app = create_router();
        let encrypt_req = serde_json::json!({
            "recipient": "invalid-key",
            "plaintext": "test"
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/encrypt")
                    .header("content-type", "application/json")
                    .body(Body::from(encrypt_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
