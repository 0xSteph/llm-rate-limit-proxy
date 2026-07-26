mod support;

use support::Server;

#[tokio::test]
async fn health_is_public_and_ok() {
    let s = Server::start().await;
    assert_eq!(s.get("/health").await.status(), 200);
}

#[tokio::test]
async fn security_headers_present_on_all_responses() {
    let s = Server::start().await;
    let r = s.get("/").await;
    let h = r.headers();
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert!(h.contains_key("content-security-policy"));
}

// --- Setup wizard + fail-closed gate ----------------------------------------

#[tokio::test]
async fn fresh_boot_is_setup_gated() {
    let s = Server::start().await;
    assert_eq!(s.get("/v1/models").await.status(), 503);
    let r = s.get("/").await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/setup");
}

#[tokio::test]
async fn wizard_claims_proxy_and_opens_v1() {
    let s = Server::start().await;
    let r = s
        .complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;
    assert!(r.status().is_success(), "setup returned {}", r.status());
    // No longer setup-gated: keyed mode now answers 401 (missing key), not 503.
    assert_eq!(s.get("/v1/models").await.status(), 401);
}

#[tokio::test]
async fn second_setup_attempt_is_rejected() {
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;
    let r = s
        .complete_wizard("evil", "hax", "p", "http://mock.test", "k")
        .await;
    assert_eq!(r.status(), 409);
}

// --- Login / logout / throttle ----------------------------------------------

#[tokio::test]
async fn protected_route_redirects_to_login_after_setup() {
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;
    let r = s.get_anon("/").await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/login");
}

#[tokio::test]
async fn login_grants_access_and_logout_revokes() {
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;

    let r = s.login("admin", "password123").await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/");

    assert_eq!(s.get("/").await.status(), 200);

    s.logout().await;
    let r = s.get("/").await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/login");
}

#[tokio::test]
async fn repeated_bad_logins_get_throttled() {
    let s = Server::start().await;
    s.complete_wizard("admin", "password123", "nim", "http://mock.test", "nvapi-x")
        .await;
    for _ in 0..5 {
        assert_eq!(s.login("admin", "wrong").await.status(), 401);
    }
    assert_eq!(s.login("admin", "wrong").await.status(), 429);
}
