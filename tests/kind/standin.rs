//! Kind-only synthetic SGLang upstream stand-in for ADR 0044 gateway smoke qualification.
//! Answers POST /v1/chat/completions with a deterministic non-streamed response carrying fixed
//! usage counts (11 prompt, 7 completion, 18 total), records received headers and JSON bodies in
//! memory, and exposes them on GET /_recorded for the smoke harness.
#![forbid(unsafe_code)]

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use bytes::Bytes;
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const RESPONSE_BODY: &str = r#"{"id":"smoke-chat-1","object":"chat.completion","created":1795450126,"model":"a","choices":[{"index":0,"message":{"role":"assistant","content":"smoke-ok","reasoning_content":null},"logprobs":null,"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18,"reasoning_tokens":0,"completion_tokens_details":null}}"#;

type Recorded = Arc<Mutex<Vec<Value>>>;

async fn healthz() -> &'static str {
    "ok"
}

async fn chat_completions(
    State(recorded): State<Recorded>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, [(header::HeaderName, &'static str); 1], &'static str) {
    let mut header_map = Map::new();
    for (name, value) in &headers {
        let key = name.as_str().to_ascii_lowercase();
        let val = value.to_str().unwrap_or("<non-utf8>").to_owned();
        header_map
            .entry(key)
            .and_modify(|existing| {
                if let Value::Array(items) = existing {
                    items.push(Value::String(val.clone()));
                }
            })
            .or_insert_with(|| Value::Array(vec![Value::String(val)]));
    }
    let parsed_body = serde_json::from_slice::<Value>(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    recorded
        .lock()
        .expect("recorded lock")
        .push(json!({"headers": header_map, "body": parsed_body}));
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        RESPONSE_BODY,
    )
}

async fn list_recorded(
    State(recorded): State<Recorded>,
) -> (StatusCode, [(header::HeaderName, &'static str); 1], Vec<u8>) {
    let snapshot = recorded.lock().expect("recorded lock").clone();
    let payload = serde_json::to_vec(&snapshot).expect("serialize recorded");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        payload,
    )
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let state: Recorded = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/_recorded", get(list_recorded))
        .with_state(state);
    let listener = TcpListener::bind("0.0.0.0:30000")
        .await
        .expect("bind 0.0.0.0:30000");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("serve stand-in");
}
