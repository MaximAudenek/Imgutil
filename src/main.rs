use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, CommandFactory, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use zeroize::Zeroizing;

use imgutil::{
    Error, decode_dir_to_file_with_progress, decode_dir_to_writer_with_progress,
    decode_file_to_file_with_progress, decode_file_to_writer_with_progress,
    encode_file_to_dir_with_progress, encode_reader_to_dir_with_progress,
};

#[derive(Parser)]
#[command(name = "imgutil")]
#[command(about = "PNG image processing utility", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate output images from an input file (or stdin if --in is omitted)
    Generate {
        #[arg(long = "in", value_name = "FILE")]
        input: Option<PathBuf>,
        #[arg(long = "out-dir", value_name = "DIRECTORY")]
        out_dir: PathBuf,
    },
    /// Extract input file from images (use --out - to write to stdout)
    #[command(group(
        ArgGroup::new("source").required(true).args(["in_dir", "in_png"])
    ))]
    Extract {
        #[arg(long = "in-dir", value_name = "DIRECTORY")]
        in_dir: Option<PathBuf>,
        #[arg(long = "in", value_name = "FILE")]
        in_png: Option<PathBuf>,
        #[arg(long = "out", value_name = "FILE")]
        out: String,
    },
}

fn read_password(stdin_is_payload: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    use std::io::IsTerminal;

    let mut stderr = std::io::stderr();
    write!(stderr, "Password: ").map_err(Error::WriteIo)?;
    stderr.flush().map_err(Error::WriteIo)?;

    if stdin_is_payload {
        // Stdin is reserved for payload bytes — must read the password from
        // /dev/tty. rpassword::read_password() opens /dev/tty directly. If no
        // controlling terminal is available the call returns an error which
        // surfaces as "Could not read file."
        let pw_string = rpassword::read_password().map_err(Error::ReadIo)?;
        return Ok(Zeroizing::new(pw_string.into_bytes()));
    }

    if std::io::stdin().is_terminal() {
        // Interactive: rpassword opens /dev/tty and disables echo.
        let pw_string = rpassword::read_password().map_err(Error::ReadIo)?;
        return Ok(Zeroizing::new(pw_string.into_bytes()));
    }

    // Piped stdin: read raw bytes directly so the password never sits in
    // StdinLock's internal BufReader. On Unix, call read(2) on fd 0 directly.
    // Non-Unix falls back to a stdin().lock().read line read.
    read_password_piped()
}

/// Read all of stdin into a Zeroizing&lt;Vec&lt;u8&gt;&gt;. The temporary stack chunk
/// is zeroed via volatile writes on exit so plaintext does not linger after
/// return. The Zeroizing wrapper handles the heap buffer.
#[cfg(unix)]
fn read_stdin_payload() -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    const CHUNK: usize = 4096;
    let mut chunk = [0u8; CHUNK];
    loop {
        // SAFETY: chunk is a valid writable [u8; CHUNK] for the duration of
        // the read; fd 0 is stdin.
        let n = unsafe {
            libc::read(0, chunk.as_mut_ptr() as *mut libc::c_void, CHUNK)
        };
        if n < 0 {
            zero_chunk(&mut chunk);
            return Err(Error::ReadIo(std::io::Error::last_os_error()));
        }
        let m = n as usize;
        if m == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..m]);
    }
    zero_chunk(&mut chunk);
    Ok(buf)
}

#[cfg(unix)]
fn zero_chunk(chunk: &mut [u8]) {
    // Volatile writes prevent the compiler from eliding the zeroing as a
    // dead store on the stack frame.
    for b in chunk.iter_mut() {
        // SAFETY: each b is a valid writable u8.
        unsafe { std::ptr::write_volatile(b as *mut u8, 0u8) };
    }
}

#[cfg(not(unix))]
fn read_stdin_payload() -> Result<Zeroizing<Vec<u8>>, Error> {
    use std::io::Read;
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut buf).map_err(Error::ReadIo)?;
    Ok(buf)
}

#[cfg(unix)]
fn read_password_piped() -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
    let mut byte = [0u8; 1];
    loop {
        // SAFETY: byte points to one valid writable byte for the duration of
        // the read; fd 0 is stdin.
        let n = unsafe {
            libc::read(0, byte.as_mut_ptr() as *mut libc::c_void, 1)
        };
        if n < 0 {
            return Err(Error::ReadIo(std::io::Error::last_os_error()));
        }
        if n == 0 {
            // EOF
            break;
        }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            break;
        }
        buf.push(byte[0]);
    }
    // Best-effort: zero the single-byte stack scratch via volatile write so
    // the compiler can't elide the store as a dead assignment.
    // SAFETY: byte is a valid writable u8.
    unsafe {
        std::ptr::write_volatile(byte.as_mut_ptr(), 0u8);
    }
    Ok(buf)
}

#[cfg(not(unix))]
fn read_password_piped() -> Result<Zeroizing<Vec<u8>>, Error> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut buf = String::new();
    stdin.lock().read_line(&mut buf).map_err(Error::ReadIo)?;
    while matches!(buf.chars().last(), Some('\n') | Some('\r')) {
        buf.pop();
    }
    Ok(Zeroizing::new(buf.into_bytes()))
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::with_template("[{bar:40.cyan/blue}] {pos}/{len} {elapsed_precise}")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
}

fn generate(input: Option<PathBuf>, out_dir: &Path) -> Result<(), Error> {
    // Pre-validate before prompting for the password and (for the stdin
    // payload path) before reading any of stdin into a buffer. Without
    // this the user types or pipes the entire payload only to be told
    // "Invalid arguments." after the fact when fs_ops finally sees the
    // bad out_dir or leftover chunk file. The fs_ops layer still does the
    // authoritative checks for any direct library callers — these are CLI
    // ergonomics on top.
    if !out_dir.is_dir() {
        return Err(Error::InvalidArgs);
    }
    if out_dir.join("chunk_0001.png").exists() {
        // Every encode produces chunk_0001.png — if it's already there the
        // encode is guaranteed to fail later. Catch it now.
        return Err(Error::InvalidArgs);
    }

    let stdin_is_payload = input.is_none();
    let password = read_password(stdin_is_payload)?;
    let mut bar: Option<ProgressBar> = None;
    let count = {
        let mut update = |done: u32, total: u32| {
            let pb = bar.get_or_insert_with(|| {
                let new_pb = ProgressBar::new(u64::from(total));
                new_pb.set_style(progress_style());
                new_pb
            });
            pb.set_length(u64::from(total));
            pb.set_position(u64::from(done));
        };
        match input {
            Some(path) => {
                encode_file_to_dir_with_progress(&path, out_dir, password, &mut update)?
            }
            None => {
                let payload = read_stdin_payload()?;
                let len: u64 =
                    payload.len().try_into().map_err(|_| Error::Capacity)?;
                let cursor = std::io::Cursor::new(payload);
                encode_reader_to_dir_with_progress(
                    cursor, len, out_dir, password, &mut update,
                )?
            }
        }
    };
    if let Some(pb) = bar {
        pb.finish_and_clear();
    }
    eprintln!("{} {}", count, out_dir.display());
    Ok(())
}

fn extract(
    in_dir: Option<PathBuf>,
    in_png: Option<PathBuf>,
    out: &str,
) -> Result<(), Error> {
    let to_stdout = out == "-";

    // Pre-validate input source and (for non-stdout) output path before
    // prompting for the password. Same rationale as generate(): surface
    // obvious typos before the user types a password.
    if let Some(ref d) = in_dir
        && !d.is_dir()
    {
        return Err(Error::InvalidArgs);
    }
    if let Some(ref f) = in_png
        && !f.is_file()
    {
        return Err(Error::InvalidArgs);
    }
    if !to_stdout && Path::new(out).exists() {
        return Err(Error::InvalidArgs);
    }

    let password = read_password(false)?;

    if to_stdout {
        // Writing to stdout: no progress bar (would corrupt the binary
        // stream) and no success message. Bytes only, exit 0.
        let stdout = std::io::stdout();
        let handle = stdout.lock();
        let noop = |_: u32, _: u32| {};
        if let Some(d) = in_dir {
            decode_dir_to_writer_with_progress(&d, handle, password, noop)?;
        } else if let Some(f) = in_png {
            decode_file_to_writer_with_progress(&f, handle, password, noop)?;
        } else {
            return Err(Error::InvalidArgs);
        }
        return Ok(());
    }

    let out_path = Path::new(out);
    let mut bar: Option<ProgressBar> = None;
    {
        let mut update = |done: u32, total: u32| {
            let pb = bar.get_or_insert_with(|| {
                let new_pb = ProgressBar::new(u64::from(total));
                new_pb.set_style(progress_style());
                new_pb
            });
            pb.set_length(u64::from(total));
            pb.set_position(u64::from(done));
        };
        if let Some(d) = in_dir {
            decode_dir_to_file_with_progress(&d, out_path, password, &mut update)?;
        } else if let Some(f) = in_png {
            decode_file_to_file_with_progress(&f, out_path, password, &mut update)?;
        } else {
            return Err(Error::InvalidArgs);
        }
    }
    if let Some(pb) = bar {
        pb.finish_and_clear();
    }
    eprintln!("{}", out_path.display());
    Ok(())
}

fn run(cli: Cli) -> Result<(), Error> {
    match cli.command {
        Cmd::Generate { input, out_dir } => generate(input, &out_dir),
        Cmd::Extract {
            in_dir,
            in_png,
            out,
        } => extract(in_dir, in_png, &out),
    }
}

fn print_invalid_args() {
    let mut cmd = <Cli as CommandFactory>::command();
    eprintln!("{}", Error::InvalidArgs.user_message());
    let _ = writeln!(std::io::stderr(), "{}", cmd.render_usage());
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            return match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    let _ = e.print();
                    ExitCode::SUCCESS
                }
                _ => {
                    print_invalid_args();
                    ExitCode::from(2)
                }
            };
        }
    };

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::InvalidArgs) => {
            print_invalid_args();
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("{}", e.user_message());
            ExitCode::from(1)
        }
    }
}
