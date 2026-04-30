use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_imgutil")
}

fn run_with_stdin(args: &[&str], stdin_data: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");
    child
        .stdin
        .as_mut()
        .expect("stdin not piped")
        .write_all(stdin_data)
        .expect("failed to write stdin");
    let out = child.wait_with_output().expect("failed to wait");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_no_stdin(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(binary())
        .args(args)
        .output()
        .expect("failed to run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn write_input(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).expect("failed to write input");
    p
}

#[test]
fn cli_help_text_is_neutral() {
    let (code, stdout, _stderr) = run_no_stdin(&["--help"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("PNG image processing utility"),
        "missing required help description"
    );
    let lc = stdout.to_lowercase();
    for forbidden in [
        "stego", "encrypt", "decrypt", "crypto", "cipher", "argon", "chacha", "secret",
    ] {
        assert!(
            !lc.contains(forbidden),
            "help text leaks {forbidden:?}: {stdout}"
        );
    }
}

#[test]
fn cli_no_args_prints_invalid_arguments_and_usage() {
    let (code, _stdout, stderr) = run_no_stdin(&[]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Invalid arguments."));
    assert!(stderr.contains("Usage:"));
}

#[test]
fn cli_unknown_subcommand_invalid_args() {
    let (code, _stdout, stderr) = run_no_stdin(&["nonsense"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Invalid arguments."));
}

#[test]
fn cli_extract_requires_one_of_in_or_in_dir() {
    // Neither --in nor --in-dir → ArgGroup violation → invalid args.
    let (code, _stdout, stderr) = run_no_stdin(&["extract", "--out", "/tmp/never_used"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Invalid arguments."));
}

#[test]
fn cli_extract_rejects_both_in_and_in_dir() {
    let (code, _stdout, stderr) = run_no_stdin(&[
        "extract",
        "--in",
        "/tmp/a.png",
        "--in-dir",
        "/tmp/b",
        "--out",
        "/tmp/c",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("Invalid arguments."));
}

#[test]
fn cli_roundtrip_via_filesystem() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = write_input(dir.path(), "input.bin", b"cli round-trip payload");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();

    // Encode
    let (code, _stdout, stderr) = run_with_stdin(
        &[
            "generate",
            "--in",
            in_path.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
        b"correct horse battery\n",
    );
    assert_eq!(code, 0, "encode failed: stderr={stderr}");
    // Success message: "<count> <out-dir>"
    assert!(
        stderr.contains("1 ") && stderr.contains(out_dir.to_str().unwrap()),
        "unexpected success message: {stderr}"
    );
    assert!(out_dir.join("chunk_0001.png").exists());

    // Decode
    let decoded = dir.path().join("decoded.bin");
    let (code, _stdout, stderr) = run_with_stdin(
        &[
            "extract",
            "--in-dir",
            out_dir.to_str().unwrap(),
            "--out",
            decoded.to_str().unwrap(),
        ],
        b"correct horse battery\n",
    );
    assert_eq!(code, 0, "decode failed: stderr={stderr}");
    assert!(stderr.contains(decoded.to_str().unwrap()));
    let recovered = std::fs::read(&decoded).unwrap();
    assert_eq!(recovered, b"cli round-trip payload");
}

#[test]
fn cli_wrong_password_authentication_failed_and_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = write_input(dir.path(), "input.bin", b"sensitive plaintext");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();

    let (code, _, _) = run_with_stdin(
        &[
            "generate",
            "--in",
            in_path.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
        b"right_password\n",
    );
    assert_eq!(code, 0);

    let decoded = dir.path().join("decoded.bin");
    let (code, stdout, stderr) = run_with_stdin(
        &[
            "extract",
            "--in-dir",
            out_dir.to_str().unwrap(),
            "--out",
            decoded.to_str().unwrap(),
        ],
        b"wrong_password\n",
    );
    assert_eq!(code, 1, "expected exit 1 on auth failure");
    assert!(
        stderr.contains("Authentication failed."),
        "stderr did not contain expected message: {stderr}"
    );
    assert!(stdout.is_empty(), "stdout must be empty on failure");
    assert!(
        !decoded.exists(),
        "partial output must be cleaned up after auth failure",
    );
}

#[test]
fn cli_refuses_to_overwrite_existing_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = write_input(dir.path(), "input.bin", b"data");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("chunk_0001.png"), b"existing").unwrap();

    let (code, _, stderr) = run_with_stdin(
        &[
            "generate",
            "--in",
            in_path.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
        b"pw\n",
    );
    assert_eq!(code, 2);
    assert!(stderr.contains("Invalid arguments."));
}

#[test]
fn cli_refuses_to_overwrite_existing_decoded_output() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = write_input(dir.path(), "input.bin", b"data");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();
    let decoded = dir.path().join("decoded.bin");

    let (code, _, _) = run_with_stdin(
        &[
            "generate",
            "--in",
            in_path.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
        b"pw\n",
    );
    assert_eq!(code, 0);
    std::fs::write(&decoded, b"pre-existing").unwrap();

    let (code, _, stderr) = run_with_stdin(
        &[
            "extract",
            "--in-dir",
            out_dir.to_str().unwrap(),
            "--out",
            decoded.to_str().unwrap(),
        ],
        b"pw\n",
    );
    assert_eq!(code, 2);
    assert!(stderr.contains("Invalid arguments."));
    // Pre-existing content untouched.
    assert_eq!(std::fs::read(&decoded).unwrap(), b"pre-existing");
}

#[test]
fn cli_extract_single_png_variant() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = write_input(dir.path(), "input.bin", b"single png decode test");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();

    let (code, _, _) = run_with_stdin(
        &[
            "generate",
            "--in",
            in_path.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
        b"pw\n",
    );
    assert_eq!(code, 0);

    let chunk = out_dir.join("chunk_0001.png");
    let decoded = dir.path().join("decoded.bin");
    let (code, _, _) = run_with_stdin(
        &[
            "extract",
            "--in",
            chunk.to_str().unwrap(),
            "--out",
            decoded.to_str().unwrap(),
        ],
        b"pw\n",
    );
    assert_eq!(code, 0);
    assert_eq!(std::fs::read(&decoded).unwrap(), b"single png decode test");
}

#[test]
fn cli_missing_input_file_reports_could_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();
    let nonexistent = dir.path().join("nope.bin");

    let (code, _, stderr) = run_with_stdin(
        &[
            "generate",
            "--in",
            nonexistent.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
        b"pw\n",
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("Could not read file."));
}

#[test]
fn cli_password_prompt_exact_string() {
    // Run a command that will fail after reading the password, and check the
    // prompt was emitted exactly. We use a missing input file so the failure
    // happens deterministically after password is read.
    let dir = tempfile::tempdir().unwrap();
    let nonexistent = dir.path().join("nope.bin");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();

    let (_code, _, stderr) = run_with_stdin(
        &[
            "generate",
            "--in",
            nonexistent.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
        b"pw\n",
    );
    // The prompt is written to stderr followed by no newline. After password
    // is read and the error is reported, stderr starts with "Password: ".
    assert!(
        stderr.starts_with("Password: "),
        "prompt is not exactly 'Password: '; got: {stderr:?}"
    );
}
