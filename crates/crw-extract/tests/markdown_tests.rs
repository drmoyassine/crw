use crw_extract::markdown::{html_to_markdown, html_to_markdown_with};

#[test]
fn markdown_empty_input() {
    let result = html_to_markdown("");
    // Should not panic
    assert!(result.is_empty() || result.trim().is_empty() || !result.contains("<"));
}

#[test]
fn markdown_table_conversion() {
    let html = r#"<table><thead><tr><th>Name</th><th>Age</th></tr></thead><tbody><tr><td>Alice</td><td>30</td></tr></tbody></table>"#;
    let md = html_to_markdown(html);
    assert!(md.contains("Name"), "Table header missing. Got: {md}");
    assert!(md.contains("Alice"), "Table data missing. Got: {md}");
    assert!(md.contains("|"), "Should use pipe for table. Got: {md}");
}

#[test]
fn markdown_code_block() {
    let html = "<pre><code>fn main() {\n    println!(\"hello\");\n}</code></pre>";
    let md = html_to_markdown(html);
    assert!(
        md.contains("```") || md.contains("    fn main()"),
        "Code should be fenced or indented. Got: {md}"
    );
}

#[test]
fn markdown_heading_levels() {
    let html = "<h1>H1</h1><h2>H2</h2><h3>H3</h3><h4>H4</h4><h5>H5</h5><h6>H6</h6>";
    let md = html_to_markdown(html);
    assert!(md.contains("# H1"), "Missing h1. Got: {md}");
    assert!(md.contains("## H2"), "Missing h2. Got: {md}");
    assert!(md.contains("### H3"), "Missing h3. Got: {md}");
}

#[test]
fn markdown_1mb_document() {
    let paragraph = "<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt.</p>\n";
    let count = 1_000_000 / paragraph.len() + 1;
    let html: String = paragraph.repeat(count);
    assert!(html.len() >= 1_000_000);

    let start = std::time::Instant::now();
    let md = html_to_markdown(&html);
    let elapsed = start.elapsed();

    assert!(!md.is_empty(), "Should produce markdown output");
    assert!(
        elapsed.as_secs() < 10,
        "1MB markdown conversion took too long: {elapsed:?}"
    );
}

#[test]
fn markdown_strips_data_uri_images() {
    let html = r#"<p>Before</p><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQABNjN9GQA"><p>After</p>"#;
    let md = html_to_markdown(html);
    assert!(
        !md.contains("data:image"),
        "data: URI should be stripped from markdown. Got: {md}"
    );
    assert!(md.contains("Before"));
    assert!(md.contains("After"));
}

/// University course pages (elte.hu) lay out each section as a one-row
/// definition table. htmd's headerless path consumed the `<th>` as a lone
/// pipe-table header and dropped the `<td>` content entirely — the page
/// rendered as headings over empty sections.
#[test]
fn markdown_definition_table_sections_survive() {
    let html = r#"<h4>Entry qualification</h4>
<table><tbody><tr><th>Entry qualification</th><td><p>Graduate / Master diploma (or higher).</p><p>Good classification.</p></td></tr></tbody></table>
<table><tbody><tr><th>Language requirements</th><td>English B2</td></tr></tbody></table>"#;
    let md = html_to_markdown_with(html, true);
    assert!(
        md.contains("**Entry qualification**"),
        "bold label missing: {md}"
    );
    assert!(
        md.contains("Graduate / Master diploma"),
        "td block content dropped: {md}"
    );
    assert!(
        md.contains("Good classification"),
        "second paragraph dropped: {md}"
    );
    assert!(md.contains("English B2"), "inline td content dropped: {md}");
}

/// Adjacent inline value cells in a definition row must not fuse into one
/// token through the full pipeline.
#[test]
fn markdown_definition_table_multi_td_values_do_not_fuse() {
    let html = r#"<h4>Fees</h4>
<table><tbody><tr><th>Fees</th><td>100 EUR</td><td>per semester</td></tr></tbody></table>"#;
    let md = html_to_markdown_with(html, true);
    assert!(
        md.contains("100 EUR per semester"),
        "adjacent inline values fused: {md}"
    );
}

/// Stray content inside a table's raw byte range survives: the
/// splice-fidelity veto leaves such tables byte-for-byte untouched, so the
/// stray renders beside the table instead of being silently deleted by the
/// splice. The table itself falls back to htmd's headerless path (row 1 as
/// header) — the pre-existing behavior for any table normalization leaves
/// alone.
#[test]
fn markdown_stray_content_inside_a_table_survives() {
    let html = "<p>Before</p><table><tbody><tr><th>Label</th><td>H</td></tr><tr><th>L2</th><td>V2</td><span>STRAY</span></tr></tbody></table><p>After</p>";
    let md = html_to_markdown_with(html, true);
    assert!(md.contains("STRAY"), "stray deleted by splice: {md}");
    assert!(md.contains("V2"), "value lost: {md}");
    assert!(
        md.contains("Before") && md.contains("After"),
        "surrounding prose disturbed: {md}"
    );
}
