use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, CommandFactory, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use zeroize::Zeroizing;

use imgutil::{
    Error, decode_dir_to_file_with_progress, decode_file_to_file_with_progress,
    encode_file_to_dir_with_progress,
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
    /// Generate output images from an input file
    Generate {
        #[arg(long = "in", value_name = "FILE")]
        input: PathBuf,
        #[arg(long = "out-dir", value_name = "DIRECTORY")]
        out_dir: PathBuf,
    },
    /// Extract input file from images
    #[command(group(
        ArgGroup::new("source").required(true).args(["in_dir", "in_png"])
    ))]
    Extract {
        #[arg(long = "in-dir", value_name = "DIRECTORY")]
        in_dir: Option<PathBuf>,
        #[arg(long = "in", value_name = "FILE")]
        in_png: Option<PathBuf>,
        #[arg(long = "out", value_name = "FILE")]
        out: PathBuf,
    },
}

fn read_password() -> Result<Zeroizing<Vec<u8>>, Error> {
    use std::io::IsTerminal;

    let mut stderr = std::io::stderr();
    write!(stderr, "Password: ").map_err(Error::WriteIo)?;
    stderr.flush().map_err(Error::WriteIo)?;

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

fn generate(input: &Path, out_dir: &Path) -> Result<(), Error> {
    let password = read_password()?;
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
        encode_file_to_dir_with_progress(input, out_dir, password, &mut update)?
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
    out: &Path,
) -> Result<(), Error> {
    let password = read_password()?;
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
            decode_dir_to_file_with_progress(&d, out, password, &mut update)?;
        } else if let Some(f) = in_png {
            decode_file_to_file_with_progress(&f, out, password, &mut update)?;
        } else {
            return Err(Error::InvalidArgs);
        }
    }
    if let Some(pb) = bar {
        pb.finish_and_clear();
    }
    eprintln!("{}", out.display());
    Ok(())
}

fn run(cli: Cli) -> Result<(), Error> {
    match cli.command {
        Cmd::Generate { input, out_dir } => generate(&input, &out_dir),
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
