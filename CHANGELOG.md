# Changelog

## Unreleased

- Added `--outline` to list visible HTML headings with selectable numbers.
- Added `--section` to retrieve a heading and its subsections by name or outline number.
- Both modes preserve output budgets, source receipts, and untrusted-content boundaries.

## 1.0.0 - 2026-09-22

- Promoted the terminal-first rewrite to stable after two independent live audits.
- Split the deadline across resolved address candidates so IPv4 and IPv6 fallback remains possible.
- Reject responses that omit `Content-Type` instead of silently treating them as plain text.

## 1.0.0rc1 - 2026-09-22

- Replaced the Windows GUI product with a dependency-free terminal tool for agents.
- Added bounded HTML-to-text extraction and JSON receipts.
- Added explicit untrusted-content boundaries and hidden-element filtering.
- Added `<main>`, `<article>`, and `role="main"` content preference.
- Added public-address validation with DNS-pinned HTTP and HTTPS connections.
- Added one deadline across DNS, redirects, connection, and response reading.
- Added redirect, error, timeout, extraction, and network-policy tests.
