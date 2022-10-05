// @author ZHOU Ling(周龄) <zhou.0@foxmail.com>
// @brief one more robust version of sshpass, but not only because of rust

// https://github.com/clap-rs/clap/blob/master/CHANGELOG.md
use clap::{Arg, ArgAction, ArgMatches, Command};
use nix::errno::Errno;
use nix::poll::{ppoll, PollFd, PollFlags};
use nix::pty::*;
use nix::sys::signal::*;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::prelude::*; // or else: 'read' method not found in `File`
use std::process::exit;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq)]
enum ErrCode {
    NoError,
    InvalidArguments,
    ConflictingArguments,
    RuntimeError,
    ParseErrror,
    IncorrectPassword,
    HostKeyUnknown,
    HostKeyChanged,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum PasswdSource {
    Stdin,
    Env,
    Fd,
    File,
    Passwd,
}

static mut DEBUG_LOG_FILE: String = String::new();
static mut PTY: OpenptyResult = OpenptyResult{master: 0, slave: 0};
static mut VERBOSE: bool = false;

macro_rules! write_log {
    ($log_file:expr, $($arg:tt)*) => {
        let data = format!($($arg)*);
        let data = format!("{}:{} {}\n", file!(), line!(), data);

        let mut file = File::options()
            .create(true)
            .append(true)
            .open($log_file)
            .expect("failed to open log file");

        file
            .write_all(data.as_bytes())
            .expect("failed to write log");
    }
}

macro_rules! debug {
    ($($arg:tt)*) => {
        #[allow(unused_unsafe)]
        unsafe {
            if VERBOSE {
                write_log!(&DEBUG_LOG_FILE, $($arg)*);
            }
        }
    }
}

macro_rules! err_return {
    ($err_code:expr, $($arg:tt)*) => {
        eprintln!($($arg)*);
        return $err_code;
    }
}

macro_rules! err_exit {
    ($err_code:expr, $($arg:tt)*) => {
        eprintln!($($arg)*);
        exit($err_code as i32);
    }
}

macro_rules! err_return_if {
    ($cond:expr, $err_code:expr, $($arg:tt)*) => {
        if ($cond) {
            err_return!($err_code, $($arg)*);
        }
    }
}

macro_rules! err_exit_if {
    ($cond:expr, $err_code:expr, $($arg:tt)*) => {
        if ($cond) {
            err_exit!($err_code, $($arg)*);
        }
    }
}

macro_rules! safe_call {
    ($call_expr:expr) => {
        loop {
            let rc = $call_expr;
            if rc < 0 {
                err_exit_if!(rc != libc::EINTR, ErrCode::RuntimeError, "{}", errno_str());
                continue;
            }

            break rc;
        }
    }
}

fn check_passwd_src(prev: PasswdSource, curr: PasswdSource) -> PasswdSource {
    err_exit_if!(prev != PasswdSource::Stdin, ErrCode::ConflictingArguments,
        "passwd source conflicts, {}: {:?}, {}: {:?}",
        "previous passwd source", prev, "current passwd source", curr);

    curr
}

fn trim_passwd(s: &str) -> String {
    let mut idx: usize = s.len();

    for (i, ch) in s.as_bytes().iter().enumerate() {
        if *ch == b'\n' {
            idx = i;
            break
        }
    }

    s[..idx].into()
}

fn write_passwd(mut file: &File, passwd: &String) {
    debug!(r#"write passwd: "{}""#, passwd);
    let data = format!("{}\n", passwd);

    file
        .write_all(data.as_bytes())
        .expect("failed to write passwd");
}

fn read_passwd() -> String {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .expect("failed to read passwd from stdin");
    line
}

fn write_prompt(data: &[u8]) {
    std::io::stdout()
        .write(data)
        .expect("failed to write input prompt");
    std::io::stdout()
        .flush()
        .expect("failed to flush stdout");
}

fn collect_remaining_args(command: &String) -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();
    let start = args.iter().position(|v| v == command).unwrap();
    args[start..].to_vec()
}

fn option_valid(matches: &ArgMatches, option: &str, index_of_command: usize) -> bool {
    return matches.contains_id(option) && matches.index_of(option).unwrap() < index_of_command;
}

fn parse_options(matches: &ArgMatches) -> (String, String, Vec<String>) {
    let command: String = matches
        .get_one::<String>("command")
        .expect(r#"failed to get "command""#)
        .into();
    let index_of_command = matches
        .index_of("command")
        .expect(r#"failed to index "command""#);
    let remaining_args = collect_remaining_args(&command);

    unsafe {
        VERBOSE = option_valid(matches, "verbose", index_of_command);
        if VERBOSE {
            DEBUG_LOG_FILE = matches
                .get_one::<String>("debug_log_file")
                .expect(r#"failed to get the value of option "-l""#)
                .into();
        }
    }

    debug!(r#"command: "{}", index_of_command: {}, remaining_args: {:?}"#,
        command, index_of_command, remaining_args);

    let mut passwd_prompt: String = "assword: ".into();
    if option_valid(matches, "passwd_prompt", index_of_command) {
        passwd_prompt = matches
            .get_one::<String>("passwd_prompt")
            .expect(r#"failed to get the value of option "-P""#)
            .into();
    }

    debug!(r#"passwd prompt: "{}""#, passwd_prompt);

    let mut passwd_src = PasswdSource::Stdin;
    let mut passwd: String = String::new();

    if option_valid(matches, "passwd_from_env", index_of_command) {
        passwd_src = check_passwd_src(passwd_src, PasswdSource::Env);

        let env_name: String = matches
            .get_one::<String>("passwd_env_name")
            .expect(r#"failed to get the value of option "-n""#)
            .into();

        passwd = std::env::var(&env_name)
            .expect(&format!("failed to get the value of env-var {:?}", &env_name));
        passwd = trim_passwd(&passwd);

        debug!(r#"passwd from env("{}"): "{}""#, env_name, passwd);
    }

    if option_valid(matches, "passwd_file", index_of_command) {
        passwd_src = check_passwd_src(passwd_src, PasswdSource::File);

        let passwd_file: String = matches
            .get_one::<String>("passwd_file")
            .expect(r#"failed to get the value of option "-f""#)
            .into();

        passwd = std::fs::read_to_string(&passwd_file)
            .expect("failed to read passwd from file");
        passwd = trim_passwd(&passwd);

        debug!(r#"passwd file: "{}", passwd from file: "{}""#, passwd_file, passwd);
    }

    if option_valid(matches, "passwd_fd", index_of_command) {
        passwd_src = check_passwd_src(passwd_src, PasswdSource::Fd);

        let passwd_fd = *matches
            .get_one::<i32>("passwd_fd")
            .expect(r#"failed to get the value of option "-d""#);

        let mut file = unsafe { File::from_raw_fd(passwd_fd) };
        let mut buffer: [u8; 128] = [0; 128];
        let n: usize = file
            .read(&mut buffer[..])
            .expect("failed to read passwd from fd");
        passwd = String::from_utf8(buffer[..n].to_vec())
            .expect("passwd is not of utf8 format");
        passwd = trim_passwd(&passwd);

        debug!(r#"passwd fd: "{}", passwd from fd: "{}""#, passwd_fd, passwd);
    }

    if option_valid(matches, "passwd", index_of_command) {
        passwd_src = check_passwd_src(passwd_src, PasswdSource::Passwd);

        passwd = matches
            .get_one::<String>("passwd")
            .expect(r#"failed to get the value of option "-p""#)
            .into();
        passwd = trim_passwd(&passwd);

        debug!(r#"passwd: "{}""#, passwd);
    }

    if passwd_src != PasswdSource::Stdin {
        err_exit_if!(passwd.is_empty(), ErrCode::InvalidArguments, "passwd should not be empty");
        return (passwd_prompt, passwd, remaining_args)
    }

    write_prompt("input passwd: ".as_bytes());
    passwd = read_passwd();
    passwd = trim_passwd(&passwd);

    debug!(r#"passwd from stdin: "{}""#, passwd);

    (passwd_prompt, passwd, remaining_args)
}

fn search(target: &[u8], mut pos: usize, data: &[u8]) -> usize {
    let mut i: usize = 0;

    while pos < target.len() && i < data.len() {
        if target[pos] == data[i] {
            pos += 1;
        } else {
            pos = 0;
            if target[pos] == data[i] {
                pos += 1;
            }
        }

        i += 1;
    }

    pos
}

fn interact(mut file: &File, passwd_prompt: &String, passwd: &String) -> ErrCode {
    static mut PASSWD_SENT: bool = false;
    static mut TOTAL_RCV_BYTES: usize = 0;
    static mut TARGET1_POS: usize = 0;
    static mut TARGET2_POS: usize = 0;

    let target1: &[u8] = passwd_prompt.as_bytes();
    let target2: &[u8] = "The authenticity of host ".as_bytes();

    let mut buffer: [u8; 256] = [0; 256];
    let n: usize = file
        .read(&mut buffer[..])
        .expect("failed to read interactive output");

    unsafe {
        TOTAL_RCV_BYTES += n;
        let data: &[u8] = &buffer[..n];

        debug!("total_rcv_bytes: {}, input data: {:?}",
            TOTAL_RCV_BYTES, String::from_utf8_lossy(data));

        TARGET1_POS = search(target1, TARGET1_POS, data);

        if TARGET1_POS == target1.len() {
            err_return_if!(PASSWD_SENT, ErrCode::IncorrectPassword, "incorrect passwd");

            write_passwd(file, passwd);
            TARGET1_POS = 0;
            PASSWD_SENT = true;
        }

        if PASSWD_SENT {
            return ErrCode::NoError;
        }

        // this can only happen before passwd prompt occurs
        TARGET2_POS = search(target2, TARGET2_POS, data);

        err_return_if!(TARGET2_POS == target2.len(), ErrCode::HostKeyUnknown, "host key unknown");
    }

    ErrCode::NoError
}

extern "C" fn sigchld_handler(_signal: libc::c_int) {
    debug!("got SIGCHLD");
}

extern "C" fn window_resize_handler(_signal: libc::c_int) {
    let ttysize = libc::winsize{ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0};

    unsafe {
        if libc::ioctl(0, libc::TIOCGWINSZ, &ttysize) == 0 {
            debug!("window resize to ({} {})", ttysize.ws_row, ttysize.ws_col);
            libc::ioctl(PTY.slave, libc::TIOCSWINSZ, &ttysize);
        } else {
            eprintln!("pid: {}, ioctl failed: {}", libc::getpid(), errno_str());
        }
    }
}

fn run(passwd_prompt: &String, passwd: &String, remaining_args: &Vec<String>) {
    unsafe {
        signal(SIGCHLD, SigHandler::Handler(sigchld_handler))
            .expect("failed to register sigchld_handler");
        signal(SIGWINCH, SigHandler::Handler(window_resize_handler))
            .expect("failed to register window_resize_handler");
    }

    let slave_dev_name = unsafe {
        PTY = openpty(None, None).expect("openpty failed");
        get_ptsname(PTY.master)
    };
    debug!("parent: pty: {:?}, slave_name: {}", PTY, slave_dev_name);

    let child_pid = unsafe { libc::fork() };

    if child_pid < 0 {
        err_exit!(ErrCode::RuntimeError, "fork failed: {}", errno_str());
    } else if child_pid == 0 {
        unsafe {
            let gid = libc::setsid();
            err_exit_if!(gid < 0, ErrCode::RuntimeError, "child: setsid failed: {}", errno_str());

            debug!("child: pty: {:?}, slave_name: {}", PTY, slave_dev_name);
            libc::close(PTY.master);
            libc::close(PTY.slave);

            let slave_dev_name_cstr = CString::new(slave_dev_name.as_bytes())
                .expect("child: failed to new CString");

            PTY.slave = libc::open(slave_dev_name_cstr.as_ptr(), libc::O_RDWR);
            err_exit_if!(PTY.slave < 0, ErrCode::RuntimeError, "child: open({}) failed: {}",
                            slave_dev_name, errno_str());

            debug!("child: close pty slave: {}", PTY.slave);
            libc::close(PTY.slave);

            debug!("child: execvp({:?})", remaining_args);
            let err = exec::execvp(&remaining_args[0], remaining_args);
            err_exit!(ErrCode::RuntimeError, "child: {}", err);
        }
    }

    let mut err_code = ErrCode::NoError;
    let mut status = 0;
    let mut sigmask = SigSet::empty();
    let sigmask_ppoll = SigSet::empty();
    let mut fds = unsafe { [PollFd::new(PTY.master, PollFlags::POLLIN)] };
    let master_file = unsafe { File::from_raw_fd(PTY.master) };

    sigmask.add(Signal::SIGCHLD);
    sigprocmask(SigmaskHow::SIG_SETMASK, Some(&sigmask), None)
          .expect("sigprocmask failed");

    loop {
        let ppoll_res = ppoll(&mut fds, None, Some(sigmask_ppoll));
        let nfds = if let Ok(nfds) = ppoll_res { nfds } else { -1 };
        debug!("nfds: {}, errno_str: {}", nfds, errno_str());

        if nfds > 0 {
            err_code = interact(&master_file, passwd_prompt, passwd);
        }

        if err_code != ErrCode::NoError {
            unsafe {
                debug!("close pty master({}), close pty slave({})", PTY.master, PTY.slave);
                libc::close(PTY.master);
                libc::close(PTY.slave);
            }
        }

        let options = if err_code == ErrCode::NoError { libc::WNOHANG } else { 0 };
        let wait_id = unsafe {
            safe_call!(libc::waitpid(child_pid, &mut status as *mut libc::c_int, options))
        };

        debug!("err_code: {:?}, wait_id: {}", err_code, wait_id);
        if err_code != ErrCode::NoError || wait_id != 0 {
            break
        }
    }

    if err_code != ErrCode::NoError {
        exit(err_code as i32);
    } else if libc::WIFEXITED(status) {
        exit(libc::WEXITSTATUS(status));
    } else {
        exit(255);
    }
}

fn errno_str() -> &'static str {
    Errno::desc(Errno::last())
}

fn get_ptsname(master_fd: RawFd) -> String {
    unsafe {
        let name_ptr = libc::ptsname(master_fd);
        err_exit_if!(name_ptr.is_null(), ErrCode::RuntimeError, "ptsname failed: {}", errno_str());

        let name = CStr::from_ptr(name_ptr);
        name.to_string_lossy().into_owned()
    }
}

fn main() {
    let matches = Command::new("rust-version sshpass")
        .trailing_var_arg(true)
        .allow_external_subcommands(true)
        .override_usage("sshpass options command args")
        .about("when no args given, password will be taken from stdin")
        .term_width(120)
        .version("1.0.0")
        .arg(Arg::new("passwd_from_env")
            .help("Input passwd from env-var")
            .short('e')
            .action(ArgAction::SetTrue))
        .arg(Arg::new("passwd_env_name")
            .help("The passwd env-var name")
            .short('n')
            .default_value("SSHPASS")
            .action(ArgAction::Set))
        .arg(Arg::new("passwd_file")
            .help("Input passwd from file")
            .short('f')
            .action(ArgAction::Set))
        .arg(Arg::new("passwd_fd")
            .help("Input passwd from file descriptor")
            .short('d')
            .action(ArgAction::Set))
        .arg(Arg::new("passwd")
            .help("Input passwd")
            .short('p')
            .action(ArgAction::Set))
        .arg(Arg::new("passwd_prompt")
            .help("Custom passwd prompt")
            .short('P')
            .action(ArgAction::Set))
        .arg(Arg::new("verbose")
            .help("Verbose output(enable debug log)")
            .short('v')
            .action(ArgAction::SetTrue))
        .arg(Arg::new("debug_log_file")
            .help("Debug log file")
            .requires("verbose")
            .short('l')
            .long("debug_log_file")
            .default_value("/tmp/sshpass.log")
            .action(ArgAction::Set))
        .arg(Arg::new("command")
            .help("Command to be executed")
            .num_args(0..) // or else: Arg::trailing_var_arg` must accept multiple values
            .index(1)
            .required(true))
        .get_matches();

    let (passwd_prompt, passwd, remaining_args) = parse_options(&matches);
    run(&passwd_prompt, &passwd, &remaining_args);
}
