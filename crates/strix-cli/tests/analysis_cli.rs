use std::{
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Input(std::path::PathBuf);
impl Input {
    fn new(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "strix-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_strix"))
            .args(args)
            .arg(&self.0)
            .output()
            .unwrap()
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
#[test]
fn utf8_jsonl_tags_and_only_no_groups_are_wired() {
    let input = Input::new("https://example.com/世界\0noise text".as_bytes());
    let out = input.run(&[
        "--only",
        "static",
        "--encoding",
        "utf8",
        "--annotate",
        "--tag",
        "url",
        "--jsonl",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records: Vec<serde_json::Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["value"], "https://example.com/世界");
    assert_eq!(records[0]["encoding"], "utf8");
    assert_eq!(records[0]["analysis"]["tags"][0], "url");
    assert!(!input.run(&["--min-trigram-score", "-5"]).status.success());
    assert!(!input.run(&["--tag", "unknown"]).status.success());
}
#[test]
fn only_base64_enables_recovery_and_json_has_provenance() {
    let input = Input::new(b"\0aGVsbG8gd29ybGQ=\0");
    let out = input.run(&["--only", "base64", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let strings = result["strings"].as_array().unwrap();
    assert!(strings.iter().all(|s| s["kind"] == "base64"));
    let found = strings
        .iter()
        .find(|s| s["value"] == "hello world")
        .unwrap();
    assert_eq!(found["analysis"]["decoded_offset"], 0);
    assert_eq!(found["location"]["offset"], 1);
    let suppressed = input.run(&["--only", "base64", "--no", "base64", "--json"]);
    let result: serde_json::Value = serde_json::from_slice(&suppressed.stdout).unwrap();
    assert!(result["strings"].as_array().unwrap().is_empty());
}

#[test]
fn model_and_negative_threshold_are_wired_without_rewriting_text() {
    let input = Input::new(b"HELLO\0");
    let model=Input::new(b"# Model Type: lowercase\n[^]\th\te\t10\nh\te\tl\t10\ne\tl\tl\t10\nl\tl\to\t10\nl\to\t[$]\t10");
    let out = input.run(&[
        "--only",
        "static",
        "--encoding",
        "ascii",
        "--model",
        model.0.to_str().unwrap(),
        "--min-trigram-score",
        "-20",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["strings"][0]["value"], "HELLO");
    assert!(
        result["strings"][0]["analysis"]["trigram_score"]
            .as_f64()
            .unwrap()
            .is_finite()
    );
}
#[test]
fn empty_file_jsonl_emits_no_records() {
    let input = Input::new(b"");
    let out = input.run(&["--jsonl"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
}
