use pretrust_core::agent::parse_jsonc;
use pretrust_core::scan_workspace;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_parser_mutation_corpus_non_panic() {
    let mutations: Vec<(&'static str, Vec<u8>)> = vec![
        // 1. UTF-8 BOM
        (
            "utf8_bom_valid",
            b"\xEF\xBB\xBF{\"version\": \"2.0.0\", \"tasks\": []}".to_vec(),
        ),
        (
            "utf8_bom_invalid",
            b"\xEF\xBB\xBF{\"version\": \"2.0.0\", tasks: [".to_vec(),
        ),
        // 2. Invalid UTF-8 bytes
        (
            "invalid_utf8_in_comment",
            b"// \xFF\xFE\xFD non utf8\n{\"tasks\": []}".to_vec(),
        ),
        (
            "invalid_utf8_in_string",
            b"{\"key\": \"\xFF\xFE\xFD\"}".to_vec(),
        ),
        (
            "invalid_utf8_truncated_seq",
            b"{\"key\": \"\xF0\x90\x80\"}".to_vec(),
        ),
        // 3. Truncated JSON
        ("truncated_object", b"{\"tasks\": [{\"label\":".to_vec()),
        ("truncated_array", b"[1, 2, 3,".to_vec()),
        ("truncated_string", b"{\"label\": \"test".to_vec()),
        ("truncated_comment", b"/* unclosed comment".to_vec()),
        // 4. Trailing garbage
        (
            "trailing_garbage_text",
            b"{\"version\": \"2.0.0\"} trailing unexpected text".to_vec(),
        ),
        (
            "trailing_garbage_null_bytes",
            b"{\"version\": \"2.0.0\"}\x00\x00\xFF".to_vec(),
        ),
        // 5. Deeply nested JSON
        (
            "deeply_nested_arrays",
            format!("{}1{}", "[".repeat(40), "]".repeat(40)).into_bytes(),
        ),
        (
            "deeply_nested_objects",
            format!("{}\"v\":1{}", "{\"a\":".repeat(40), "}".repeat(40)).into_bytes(),
        ),
        // 6. Extreme/empty cases
        ("empty", b"".to_vec()),
        ("whitespace_only", b"   \t\r\n   ".to_vec()),
        ("lone_bom", b"\xEF\xBB\xBF".to_vec()),
        ("lone_brace", b"{".to_vec()),
        ("lone_bracket", b"[".to_vec()),
        ("lone_slash", b"/".to_vec()),
        ("lone_null", b"\x00".to_vec()),
    ];

    for (name, raw_bytes) in &mutations {
        let lossy_str = String::from_utf8_lossy(raw_bytes);

        // Assert parse_jsonc does not panic on any input
        let _ = parse_jsonc(&lossy_str);

        // Put into .vscode/tasks.json in a workspace and ensure scan_workspace does not panic
        let dir = tempdir().expect("tempdir");
        let vscode = dir.path().join(".vscode");
        fs::create_dir_all(&vscode).expect("create_dir");
        fs::write(vscode.join("tasks.json"), raw_bytes).expect("write file");

        let findings = scan_workspace(dir.path());
        // For malformed/truncated/garbage JSON, agent scanner must refuse with PT-CFG-001 or find nothing
        if name.starts_with("truncated")
            || name.starts_with("trailing")
            || name == &"utf8_bom_invalid"
            || name == &"lone_brace"
            || name == &"lone_bracket"
        {
            assert!(
                findings.iter().any(|f| f.id == "PT-CFG-001"),
                "Mutation '{}' should have triggered PT-CFG-001 refusal, got: {:?}",
                name,
                findings
            );
        }
    }
}
