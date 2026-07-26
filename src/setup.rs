//! First-run wizard: the very first visitor claims the proxy by creating the
//! superuser and the first provider key. Until that happens the data plane is
//! closed and browsers are sent here; afterwards this surface is inert.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::{auth, config, AppState};

const SETUP_HTML: &str = r#"<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>Sluice — Setup</title>
<h1>Claim this Sluice</h1>
<p>The first visitor becomes the superuser. Add your admin login and one upstream provider key.</p>
<form method=post action=/setup>
  <p><input name=username placeholder="Admin username" autofocus></p>
  <p><input name=password type=password placeholder="Admin password"></p>
  <hr>
  <p><input name=provider_name placeholder="Provider name (e.g. nim)"></p>
  <p><input name=base_url placeholder="Provider base URL"></p>
  <p><input name=api_key placeholder="Provider API key"></p>
  <p><button type=submit>Finish setup</button></p>
</form>"#;

pub async fn setup_page(State(state): State<Arc<AppState>>) -> Response {
    if !state.setup_required.load(Ordering::Relaxed) {
        return Redirect::to("/login").into_response();
    }
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        SETUP_HTML,
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct SetupForm {
    username: String,
    password: String,
    provider_name: String,
    base_url: String,
    api_key: String,
}

pub async fn setup_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<SetupForm>,
) -> Response {
    // Fail closed: only the first, one-time claim is honored.
    if !state.setup_required.load(Ordering::Relaxed) {
        return (StatusCode::CONFLICT, "setup already complete").into_response();
    }
    if form.username.trim().is_empty() || form.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "username and password are required",
        )
            .into_response();
    }

    let (secret, client_rec) = auth::new_client_key("default", &form.username);
    {
        // Hold the store mutex across the whole build → save so a second concurrent
        // claim can't interleave.
        let mut store = state.store.lock().unwrap();
        if store.superuser().is_some() {
            return (StatusCode::CONFLICT, "setup already complete").into_response();
        }
        store.users.push(config::User {
            username: form.username.clone(),
            pw_hash: auth::hash_password(&form.password),
            role: config::Role::Superuser,
        });
        store.providers.push(config::Provider {
            name: form.provider_name.clone(),
            base_url: form.base_url.trim_end_matches('/').to_string(),
            keys: vec![config::ProviderKey {
                key: form.api_key.clone(),
                enabled: true,
                rpm: 40,
                owner: form.username.clone(),
            }],
        });
        store.clients.push(client_rec);
        if let Err(e) = config::save(&state.data_dir, &store) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not save config: {e}"),
            )
                .into_response();
        }
    }
    state.setup_required.store(false, Ordering::Relaxed);

    Html(format!(
        "<!doctype html><meta charset=utf-8><title>Sluice — Ready</title>\
         <h1>Setup complete</h1>\
         <p>Your client API key (shown only once — copy it now):</p>\
         <pre>{}</pre>\
         <p><a href=\"/login\">Sign in to the dashboard</a></p>",
        html_escape(&secret)
    ))
    .into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
