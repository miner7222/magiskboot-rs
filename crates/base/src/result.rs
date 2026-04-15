use crate::logging::Formatter;
use crate::{LogLevel, log_with_args, log_with_formatter};
use std::fmt;
use std::fmt::Display;
use std::panic::Location;

// Error handling: all errors should be logged and consumed as soon as possible,
// then converted into LoggedError. For Result with Display errors, the ? operator
// will log and convert automatically.

#[derive(Default)]
pub struct LoggedError {}
pub type LoggedResult<T> = Result<T, LoggedError>;

#[macro_export]
macro_rules! log_err {
    () => {{
        Err($crate::LoggedError::default())
    }};
    ($($args:tt)+) => {{
        $crate::error!($($args)+);
        Err($crate::LoggedError::default())
    }};
}

pub trait SilentLogExt<T> {
    fn silent(self) -> LoggedResult<T>;
}

impl<T, E> SilentLogExt<T> for Result<T, E> {
    fn silent(self) -> LoggedResult<T> {
        self.map_err(|_| LoggedError::default())
    }
}

impl<T> SilentLogExt<T> for Option<T> {
    fn silent(self) -> LoggedResult<T> {
        self.ok_or_else(LoggedError::default)
    }
}

pub trait ResultExt<T> {
    fn log(self) -> LoggedResult<T>;
    fn log_with_msg<F: FnOnce(Formatter) -> fmt::Result>(self, f: F) -> LoggedResult<T>;
    fn log_ok(self);
}

pub trait OptionExt<T> {
    fn ok_or_log(self) -> LoggedResult<T>;
    fn ok_or_log_msg<F: FnOnce(Formatter) -> fmt::Result>(self, f: F) -> LoggedResult<T>;
}

impl<T> OptionExt<T> for Option<T> {
    #[inline(always)]
    fn ok_or_log(self) -> LoggedResult<T> {
        self.ok_or_else(LoggedError::default)
    }

    #[cfg(not(debug_assertions))]
    fn ok_or_log_msg<F: FnOnce(Formatter) -> fmt::Result>(self, f: F) -> LoggedResult<T> {
        self.ok_or_else(|| {
            do_log_msg(LogLevel::Error, None, f);
            LoggedError::default()
        })
    }

    #[track_caller]
    #[cfg(debug_assertions)]
    fn ok_or_log_msg<F: FnOnce(Formatter) -> fmt::Result>(self, f: F) -> LoggedResult<T> {
        let caller = Some(Location::caller());
        self.ok_or_else(|| {
            do_log_msg(LogLevel::Error, caller, f);
            LoggedError::default()
        })
    }
}

trait Loggable {
    fn do_log(self, level: LogLevel, caller: Option<&'static Location>) -> LoggedError;
    fn do_log_msg<F: FnOnce(Formatter) -> fmt::Result>(
        self,
        level: LogLevel,
        caller: Option<&'static Location>,
        f: F,
    ) -> LoggedError;
}

impl<T, E: Loggable> ResultExt<T> for Result<T, E> {
    #[cfg(not(debug_assertions))]
    fn log(self) -> LoggedResult<T> {
        self.map_err(|e| e.do_log(LogLevel::Error, None))
    }

    #[track_caller]
    #[cfg(debug_assertions)]
    fn log(self) -> LoggedResult<T> {
        let caller = Some(Location::caller());
        self.map_err(|e| e.do_log(LogLevel::Error, caller))
    }

    #[cfg(not(debug_assertions))]
    fn log_with_msg<F: FnOnce(Formatter) -> fmt::Result>(self, f: F) -> LoggedResult<T> {
        self.map_err(|e| e.do_log_msg(LogLevel::Error, None, f))
    }

    #[track_caller]
    #[cfg(debug_assertions)]
    fn log_with_msg<F: FnOnce(Formatter) -> fmt::Result>(self, f: F) -> LoggedResult<T> {
        let caller = Some(Location::caller());
        self.map_err(|e| e.do_log_msg(LogLevel::Error, caller, f))
    }

    #[cfg(not(debug_assertions))]
    fn log_ok(self) {
        self.map_err(|e| e.do_log(LogLevel::Error, None)).ok();
    }

    #[track_caller]
    #[cfg(debug_assertions)]
    fn log_ok(self) {
        let caller = Some(Location::caller());
        self.map_err(|e| e.do_log(LogLevel::Error, caller)).ok();
    }
}

impl<T> ResultExt<T> for LoggedResult<T> {
    fn log(self) -> LoggedResult<T> {
        self
    }

    #[cfg(not(debug_assertions))]
    fn log_with_msg<F: FnOnce(Formatter) -> fmt::Result>(self, f: F) -> LoggedResult<T> {
        self.inspect_err(|_| do_log_msg(LogLevel::Error, None, f))
    }

    #[track_caller]
    #[cfg(debug_assertions)]
    fn log_with_msg<F: FnOnce(Formatter) -> fmt::Result>(self, f: F) -> LoggedResult<T> {
        let caller = Some(Location::caller());
        self.inspect_err(|_| do_log_msg(LogLevel::Error, caller, f))
    }

    fn log_ok(self) {}
}

// Allow converting Loggable errors to LoggedError for ? operator
impl<T: Loggable> From<T> for LoggedError {
    #[cfg(not(debug_assertions))]
    fn from(e: T) -> Self {
        e.do_log(LogLevel::Error, None)
    }

    #[track_caller]
    #[cfg(debug_assertions)]
    fn from(e: T) -> Self {
        let caller = Some(Location::caller());
        e.do_log(LogLevel::Error, caller)
    }
}

// Make all Display types Loggable
impl<T: Display> Loggable for T {
    fn do_log(self, level: LogLevel, caller: Option<&'static Location>) -> LoggedError {
        if let Some(caller) = caller {
            log_with_args!(level, "[{}:{}] {:#}", caller.file(), caller.line(), self);
        } else {
            log_with_args!(level, "{:#}", self);
        }
        LoggedError::default()
    }

    fn do_log_msg<F: FnOnce(Formatter) -> fmt::Result>(
        self,
        level: LogLevel,
        caller: Option<&'static Location>,
        f: F,
    ) -> LoggedError {
        log_with_formatter(level, |w| {
            if let Some(caller) = caller {
                write!(w, "[{}:{}] ", caller.file(), caller.line())?;
            }
            f(w)?;
            writeln!(w, ": {self:#}")
        });
        LoggedError::default()
    }
}

fn do_log_msg<F: FnOnce(Formatter) -> fmt::Result>(
    level: LogLevel,
    caller: Option<&'static Location>,
    f: F,
) {
    log_with_formatter(level, |w| {
        if let Some(caller) = caller {
            write!(w, "[{}:{}] ", caller.file(), caller.line())?;
        }
        f(w)?;
        w.write_char('\n')
    });
}
