use crate::{Utf8CStr, cstr};
use std::fmt;
use std::io::{Write, stderr, stdout};
use std::process::exit;

#[derive(Copy, Clone)]
struct LogFlag(u32);

impl LogFlag {
    const EMPTY: Self = Self(0);
    const DISABLE_ERROR: u32 = 1 << 0;
    const DISABLE_WARN: u32 = 1 << 1;
    const DISABLE_INFO: u32 = 1 << 2;
    const DISABLE_DEBUG: u32 = 1 << 3;
    const EXIT_ON_ERROR: u32 = 1 << 4;

    fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    fn set(&mut self, flag: u32, value: bool) {
        if value {
            self.0 |= flag;
        } else {
            self.0 &= !flag;
        }
    }
}

#[derive(Copy, Clone)]
#[repr(i32)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

pub static mut LOGGER: Logger = Logger {
    write: |_, _| {},
    flags: LogFlag::EMPTY,
};

type LogWriter = fn(level: LogLevel, msg: &Utf8CStr);
pub(crate) type Formatter<'a> = &'a mut dyn fmt::Write;

#[derive(Copy, Clone)]
pub struct Logger {
    pub write: LogWriter,
    flags: LogFlag,
}

pub fn update_logger(f: impl FnOnce(&mut Logger)) {
    let mut logger = unsafe { LOGGER };
    f(&mut logger);
    unsafe {
        LOGGER = logger;
    }
}

pub fn exit_on_error(b: bool) {
    update_logger(|logger| logger.flags.set(LogFlag::EXIT_ON_ERROR, b));
}

impl LogLevel {
    fn as_disable_flag(&self) -> u32 {
        match *self {
            LogLevel::Error => LogFlag::DISABLE_ERROR,
            LogLevel::Warn => LogFlag::DISABLE_WARN,
            LogLevel::Info => LogFlag::DISABLE_INFO,
            LogLevel::Debug => LogFlag::DISABLE_DEBUG,
        }
    }
}

pub fn set_log_level_state(level: LogLevel, enabled: bool) {
    update_logger(|logger| logger.flags.set(level.as_disable_flag(), enabled));
}

fn log_with_writer<F: FnOnce(LogWriter)>(level: LogLevel, f: F) {
    let logger = unsafe { LOGGER };
    if logger.flags.contains(level.as_disable_flag()) {
        return;
    }
    f(logger.write);
    if matches!(level, LogLevel::Error) && logger.flags.contains(LogFlag::EXIT_ON_ERROR) {
        exit(-1);
    }
}

pub fn log_with_formatter<F: FnOnce(Formatter) -> fmt::Result>(level: LogLevel, f: F) {
    log_with_writer(level, |write| {
        let mut buf = cstr::buf::default();
        f(&mut buf).ok();
        write(level, &buf);
    });
}

pub fn cmdline_logging() {
    fn cmdline_write(level: LogLevel, msg: &Utf8CStr) {
        if matches!(level, LogLevel::Info) {
            stdout().write_all(msg.as_bytes()).ok();
        } else {
            stderr().write_all(msg.as_bytes()).ok();
        }
    }
    update_logger(|logger| logger.write = cmdline_write);
}

#[macro_export]
macro_rules! log_with_args {
    ($level:expr, $($args:tt)+) => {
        $crate::log_with_formatter($level, |w| writeln!(w, $($args)+))
    }
}

#[macro_export]
macro_rules! error {
    ($($args:tt)+) => {
        $crate::log_with_formatter($crate::LogLevel::Error, |w| writeln!(w, $($args)+))
    }
}

#[macro_export]
macro_rules! warn {
    ($($args:tt)+) => {
        $crate::log_with_formatter($crate::LogLevel::Warn, |w| writeln!(w, $($args)+))
    }
}

#[macro_export]
macro_rules! info {
    ($($args:tt)+) => {
        $crate::log_with_formatter($crate::LogLevel::Info, |w| writeln!(w, $($args)+))
    }
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! debug {
    ($($args:tt)+) => {
        $crate::log_with_formatter($crate::LogLevel::Debug, |w| writeln!(w, $($args)+))
    }
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! debug {
    ($($args:tt)+) => {};
}
