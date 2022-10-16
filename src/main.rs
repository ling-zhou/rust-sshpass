// @author ZHOU Ling(周龄) <zhou.0@foxmail.com>
// @brief one more robust version of sshpass, but not only because of rust

// https://github.com/clap-rs/clap/blob/master/CHANGELOG.md
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use nix::errno::Errno;
use nix::poll::{ppoll, PollFd, PollFlags};
use nix::pty::*;
use nix::sys::signal::*;
use nix::sys::time::{TimeSpec, TimeValLike};
use nix::unistd::Pid;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::prelude::*; // or else: 'read' method not found in `File`
use std::process::exit;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

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
static mut DEBUG: bool = false;
static mut GOT_CHILD_SIGNAL: AtomicBool = AtomicBool::new(false);
static mut GOT_EXIT_SIGNAL: AtomicBool = AtomicBool::new(false);

macro_rules! close_pty {
    ($name:expr) => {
        debug!("{}: close pty master({}), close pty slave({})", $name, PTY.master, PTY.slave);

        #[allow(unused_unsafe)]
        unsafe {
            libc::close(PTY.master);
            libc::close(PTY.slave);
        }
    }
}

macro_rules! write_log {
    ($($arg:tt)*) => {
        #[allow(unused_unsafe)]
        unsafe {
            let data = format!($($arg)*);
            let data = format!("{}:{} {}\n", file!(), line!(), data);

            let mut file = File::options()
                .create(true)
                .append(true)
                .open(&DEBUG_LOG_FILE)
                .expect("failed to open log file");

            file
                .write_all(data.as_bytes())
                .expect("failed to write log");
        }
    }
}

macro_rules! debug {
    ($($arg:tt)*) => {
        #[allow(unused_unsafe)]
        if unsafe { DEBUG } {
            write_log!($($arg)*);
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

macro_rules! no_eintr_call {
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

fn option_present(matches: &ArgMatches, option: &str, index_of_command: usize) -> bool {
    return matches.contains_id(option) && matches.index_of(option).unwrap() < index_of_command;
}

extern "C" fn window_resize_handler(signal: libc::c_int) {
    let ttysize = libc::winsize{ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0};

    unsafe {
        if libc::ioctl(0, libc::TIOCGWINSZ, &ttysize) == 0 {
            debug!("got signal: {}({:?}), window resize to ({}, {})",
                    signal, signal_str(signal), ttysize.ws_row, ttysize.ws_col);
            libc::ioctl(PTY.slave, libc::TIOCSWINSZ, &ttysize);
        } else {
            eprintln!("pid: {}, ioctl failed: {}", libc::getpid(), errno_str());
        }
    }
}

extern "C" fn child_handler(signal: libc::c_int) {
    debug!("got signal: {}({:?})", signal, signal_str(signal));
    unsafe { GOT_CHILD_SIGNAL.store(true, Ordering::Relaxed); }
}

extern "C" fn exit_handler(signal: libc::c_int) {
    debug!("got signal: {}({:?})", signal, signal_str(signal));
    unsafe { GOT_EXIT_SIGNAL.store(true, Ordering::Relaxed); }
}

fn register_signal_handler(signum: Signal, handler: extern fn(libc::c_int)) {
    unsafe {
        signal(signum, SigHandler::Handler(handler))
            .expect("failed to register signal handler");
    }
}

fn got_child_signal() -> bool {
    return unsafe { GOT_CHILD_SIGNAL.load(Ordering::Relaxed) };
}

fn got_exit_signal() -> bool {
    return unsafe { GOT_EXIT_SIGNAL.load(Ordering::Relaxed) };
}

fn need_exit() -> bool {
    return got_child_signal() || got_exit_signal();
}

fn kill_child_process(pid: i32) {
    debug!("kill child process({})", pid);

    match kill(Pid::from_raw(pid), SIGTERM) {
        Ok(_) => (),
        Err(Errno::ESRCH) => {
            debug!("child process({}) is already dead", pid)
        },
        Err(x) => {
            err_exit!(ErrCode::RuntimeError, "failed to kill child process({}): {}",
                        pid, Errno::desc(x));
        }
    }
}

fn waitpid(pid: i32, status: &mut i32, options: i32) -> i32 {
    unsafe {
        no_eintr_call!(libc::waitpid(pid, status as *mut libc::c_int, options))
    }
}

fn errno_str() -> &'static str {
    Errno::desc(Errno::last())
}

fn signal_str(signal: i32) -> String {
    ptr_to_str(unsafe { libc::strsignal(signal) }, "strsignal")
}

fn get_ptsname(master_fd: RawFd) -> String {
    ptr_to_str(unsafe { libc::ptsname(master_fd) }, "ptsname")
}

fn ptr_to_str(ptr: *mut libc::c_char, func: &str) -> String {
    err_exit_if!(ptr.is_null(), ErrCode::RuntimeError, "{} failed: {}", func, errno_str());

    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_string_lossy().into_owned()
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

fn run(passwd_prompt: &String, passwd: &String, remaining_args: &Vec<String>) {
    register_signal_handler(SIGWINCH, window_resize_handler);
    register_signal_handler(SIGCHLD, child_handler);
    register_signal_handler(SIGINT, exit_handler);
    register_signal_handler(SIGHUP, exit_handler);
    register_signal_handler(SIGTERM, exit_handler);

    let slave_dev_name = unsafe {
        PTY = openpty(None, None).expect("openpty failed");
        get_ptsname(PTY.master)
    };
    debug!("pty: {:?}, slave_name: {}", PTY, slave_dev_name);

    let child_pid = unsafe { libc::fork() };

    if child_pid < 0 {
        err_exit!(ErrCode::RuntimeError, "fork failed: {}", errno_str());
    } else if child_pid == 0 {
        unsafe {
            let gid = libc::setsid();
            err_exit_if!(gid < 0, ErrCode::RuntimeError, "child: setsid failed: {}", errno_str());

            close_pty!("child");

            let slave_dev_name_cstr = CString::new(slave_dev_name.as_bytes())
                .expect("child: failed to new CString");

            PTY.slave = libc::open(slave_dev_name_cstr.as_ptr(), libc::O_RDWR);
            err_exit_if!(PTY.slave < 0, ErrCode::RuntimeError, "child: open({}) failed: {}",
                            slave_dev_name, errno_str());

            debug!("child: close pty slave: {}", PTY.slave);
            libc::close(PTY.slave); // we do not need it open

            debug!("child: execvp({:?})", remaining_args);
            let err = exec::execvp(&remaining_args[0], remaining_args);
            err_exit!(ErrCode::RuntimeError, "child: {}", err);
        }
    }

    let mut err_code = ErrCode::NoError;
    let mut status = 0;
    let mut fds = unsafe { [PollFd::new(PTY.master, PollFlags::POLLIN)] };
    let master_file = unsafe { File::from_raw_fd(PTY.master) };
    let ppoll_timeout = TimeSpec::milliseconds(500);
    let ppoll_sigmask = SigSet::empty();

    loop {
        let options = if err_code == ErrCode::NoError && !need_exit() { libc::WNOHANG } else { 0 };

        if err_code != ErrCode::NoError {
            close_pty!("parent");
        }

        if need_exit() {
            kill_child_process(child_pid);
        }

        let wait_id = waitpid(child_pid, &mut status, options);
        // debug!("need_exit: {:?}, options: {:?}, err_code: {:?}, wait_id: {:?}, status: {:?}",
        //    need_exit(), options, err_code, wait_id, status);

        if wait_id != 0 {
            break
        }

        let ppoll_res = ppoll(&mut fds, Some(ppoll_timeout), Some(ppoll_sigmask));
        let nfds = if let Ok(nfds) = ppoll_res { nfds } else { -1 };
        // debug!("nfds: {}, errno_str: {}", nfds, errno_str());

        if nfds > 0 {
            err_code = interact(&master_file, passwd_prompt, passwd);
        }
    }

    close_pty!("parent");

    if err_code != ErrCode::NoError {
        exit(err_code as i32);
    } else if libc::WIFEXITED(status) {
        exit(libc::WEXITSTATUS(status));
    } else {
        exit(255);
    }
}

fn parse_options(matches: &ArgMatches) -> (String, String, Vec<String>) {
    let command = matches
        .get_one::<String>("command")
        .expect(r#"failed to get "command""#)
        .into();
    let index_of_command = matches
        .index_of("command")
        .expect(r#"failed to index "command""#);
    let remaining_args = collect_remaining_args(&command);

    unsafe {
        DEBUG = option_present(matches, "debug", index_of_command);
        if DEBUG {
            DEBUG_LOG_FILE = matches
                .get_one::<String>("debug-log-file")
                .expect(r#"failed to get the value of option "-l""#)
                .into();
        }
    }

    debug!(r#"command: "{}", index_of_command: {}, remaining_args: {:?}"#,
        command, index_of_command, remaining_args);

    let passwd_prompt = matches
        .get_one::<String>("passwd_prompt")
        .expect(r#"failed to get the value of option "-P""#)
        .into();

    debug!(r#"passwd prompt: "{}""#, passwd_prompt);

    let mut passwd_src = PasswdSource::Stdin;
    let mut passwd: String = String::new();

    if option_present(matches, "passwd_from_env", index_of_command) {
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

    if option_present(matches, "passwd_file", index_of_command) {
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

    if option_present(matches, "passwd_fd", index_of_command) {
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

    if option_present(matches, "passwd", index_of_command) {
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

fn register_options() -> ArgMatches {
    return Command::new("rust-version sshpass")
        .about("noninteractive ssh password provider.\n\
            when no passwd given, it will be taken from stdin.")
        .after_help("report bugs to <https://github.com/ling-zhou/rust-sshpass>.")
        .override_usage("sshpass options command options_of_command")
        .allow_external_subcommands(true)
        .trailing_var_arg(true)
        .term_width(120)
        .version("1.1.4")
        .arg(Arg::new("passwd_from_env")
            .help("Input passwd from env-var")
            .short('e')
            .action(ArgAction::SetTrue))
        .arg(Arg::new("passwd_env_name")
            .help("Customize passwd env-var name")
            .requires("passwd_from_env")
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
            .action(ArgAction::Set)
            .value_parser(value_parser!(i32)))
        .arg(Arg::new("passwd")
            .help("Input passwd")
            .short('p')
            .action(ArgAction::Set))
        .arg(Arg::new("passwd_prompt")
            .help("Customize passwd prompt")
            .short('P')
            .default_value("assword: ")
            .action(ArgAction::Set))
        .arg(Arg::new("debug")
            .help("Verbose output(enable debug log)")
            .alias("verbose")
            .short('v')
            .long("debug")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("debug-log-file")
            .help("Debug log file")
            .requires("debug")
            .short('l')
            .long("debug-log-file")
            .default_value("/dev/stderr")
            .action(ArgAction::Set))
        .arg(Arg::new("command")
            .help("Command to be executed")
            .num_args(0..) // or else: Arg::trailing_var_arg` must accept multiple values
            .index(1)
            .required(true))
        .get_matches();
}

fn main() {
    let (passwd_prompt, passwd, remaining_args) = parse_options(&register_options());
    run(&passwd_prompt, &passwd, &remaining_args);
}
