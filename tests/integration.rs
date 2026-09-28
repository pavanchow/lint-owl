//! Public-API integration tests for lint-owl, exercised the way a downstream
//! consumer would: through `analyze`, `analyze_cfg`, `analyze_lang`, the JSON
//! and SARIF emitters, and the `Config`/`Lang`/`Finding` surface.

use lint_owl::{
    analyze, analyze_cfg, analyze_lang, config_for, lang_from_ext, python_config, sarif, scan_json,
    severity, Lang,
};

#[test]
fn direct_taint_flow_is_reported_source_to_sink() {
    let src = "x = input()\nos.system(x)\n";
    let findings = analyze(src);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.vuln, "command-injection");
    assert_eq!(f.severity(), "critical");
    // The path threads the untrusted source line to the dangerous sink line.
    assert_eq!(f.source_line(), 1);
    assert_eq!(f.sink_line(), 2);
    assert_eq!(f.path, vec![1, 2]);
}

#[test]
fn a_sanitizer_on_the_flow_suppresses_the_finding() {
    // int() neutralizes command-injection taint; no finding should survive.
    let clean = analyze("x = int(input())\nos.system(x)\n");
    assert!(clean.is_empty(), "sanitized flow should not report: {clean:?}");
    // Sanity check the same shape fires without the sanitizer.
    assert_eq!(analyze("x = input()\nos.system(x)\n").len(), 1);
}

#[test]
fn ssrf_flow_is_high_not_critical() {
    let findings = analyze("u = request.args.get(\"url\")\nrequests.get(u)\n");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vuln, "ssrf");
    assert_eq!(findings[0].severity(), "high");
}

#[test]
fn sql_injection_via_execute_suffix_sink() {
    // `.execute` is a suffix sink, so a method call on any receiver matches.
    let findings = analyze("q = request.args.get(\"q\")\ncur.execute(q)\n");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vuln, "sql-injection");
    assert_eq!(findings[0].severity(), "critical");
}

#[test]
fn insecure_deserialization_is_detected() {
    let findings = analyze("d = input()\npickle.loads(d)\n");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vuln, "insecure-deserialization");
    assert_eq!(findings[0].severity(), "critical");
}

#[test]
fn clean_and_minimal_inputs_report_nothing() {
    // Empty input.
    assert!(analyze("").is_empty());
    // A source with no reachable sink.
    assert!(analyze("x = input()\n").is_empty());
    // A sink with no tainted argument.
    assert!(analyze("os.system(\"ls\")\n").is_empty());
}

#[test]
fn severity_classification_matches_the_public_helper() {
    assert_eq!(severity("command-injection"), "critical");
    assert_eq!(severity("sql-injection"), "critical");
    assert_eq!(severity("insecure-deserialization"), "critical");
    assert_eq!(severity("ssrf"), "high");
    assert_eq!(severity("path-traversal"), "high");
    // Unknown classes default to high, never panic.
    assert_eq!(severity("anything-else"), "high");
}

#[test]
fn language_selection_maps_extensions_and_analyzes_js() {
    assert_eq!(lang_from_ext("app.js"), Lang::Js);
    assert_eq!(lang_from_ext("app.ts"), Lang::Js);
    assert_eq!(lang_from_ext("index.php"), Lang::Php);
    assert_eq!(lang_from_ext("main.py"), Lang::Python);
    assert_eq!(lang_from_ext("README"), Lang::Python); // default

    let cfg = config_for(Lang::Js);
    let findings = analyze_lang("const x = req.query.cmd;\nexec(x);\n", Lang::Js, &cfg);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vuln, "command-injection");
}

#[test]
fn php_superglobal_source_reaches_a_command_sink() {
    let cfg = config_for(Lang::Php);
    let findings = analyze_lang("system($_GET[\"cmd\"]);\n", Lang::Php, &cfg);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vuln, "command-injection");
    assert_eq!(findings[0].severity(), "critical");
}

#[test]
fn scan_json_shape_carries_count_severity_and_tagged_hops() {
    let json = scan_json("x = input()\nos.system(x)\n").to_string();
    assert!(json.contains("\"count\":1"), "{json}");
    assert!(json.contains("command-injection"));
    assert!(json.contains("\"severity\":\"critical\""));
    assert!(json.contains("\"tag\":\"source\""));
    assert!(json.contains("\"tag\":\"sink\""));
}

#[test]
fn sarif_output_is_well_formed_2_1_0() {
    let src = "x = input()\nos.system(x)\n".to_string();
    let findings = analyze(&src);
    let doc = sarif(&[("app.py".to_string(), src, findings)]).to_string();
    assert!(doc.contains("\"version\":\"2.1.0\""), "{doc}");
    assert!(doc.contains("\"ruleId\":\"command-injection\""));
    // Critical findings map to SARIF level "error".
    assert!(doc.contains("\"level\":\"error\""));
    assert!(doc.contains("codeFlows"));
}

#[test]
fn many_independent_flows_are_all_counted() {
    // Multi-unit case: N distinct source->sink pairs must yield exactly N
    // findings, catching any dedup or counter off-by-one.
    let mut src = String::new();
    for i in 0..40 {
        src.push_str(&format!("a{i} = input()\nos.system(a{i})\n"));
    }
    let findings = analyze(&src);
    assert_eq!(findings.len(), 40);
    assert!(findings.iter().all(|f| f.vuln == "command-injection"));
}

#[test]
fn analysis_is_deterministic() {
    let src = "u = request.args.get(\"url\")\nrequests.get(u)\nx = input()\nos.system(x)\n";
    let a: Vec<_> = analyze_cfg(src, &python_config()).into_iter().map(|f| (f.vuln, f.path)).collect();
    let b: Vec<_> = analyze_cfg(src, &python_config()).into_iter().map(|f| (f.vuln, f.path)).collect();
    assert_eq!(a, b);
}
