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
