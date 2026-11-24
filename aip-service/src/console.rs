//! Static shell only. All displayed records use the authenticated read API.
use axum::http::{header, HeaderMap, HeaderValue};

fn asset(body: &'static str, content_type: &'static str) -> (HeaderMap, &'static str) {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("content-security-policy", HeaderValue::from_static(
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"));
    (headers, body)
}
pub async fn index() -> (HeaderMap, &'static str) {
    asset(
        include_str!("../../integrations/enterprise-console/index.html"),
        "text/html; charset=utf-8",
    )
}
pub async fn script() -> (HeaderMap, &'static str) {
    asset(
        include_str!("../../integrations/enterprise-console/app.js"),
        "application/javascript; charset=utf-8",
    )
}
pub async fn style() -> (HeaderMap, &'static str) {
    asset(
        include_str!("../../integrations/enterprise-console/style.css"),
        "text/css; charset=utf-8",
    )
}
