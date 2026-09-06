//! Process resource limits that matter for a tool that opens thousands of sockets.
//!
//! macOS gives GUI apps launched from Finder a soft limit of only 256 open files, and a
//! connect attempt that fails with `EMFILE` looks exactly like a closed port. We raise the
//! limit as far as the OS allows and size the scanner's socket budget from the result.

/// Highest soft limit we ask for. macOS refuses values above `OPEN_MAX` (10240) when the
/// hard limit is unlimited, and this is plenty for a scanner.
const TARGET_OPEN_FILES: u64 = 10_240;

/// File descriptors kept in reserve for the runtime, DNS lookups, child processes, etc.
const RESERVED_FDS: u64 = 64;

/// Hard cap on simultaneous sockets regardless of the fd limit.
const MAX_SOCKET_BUDGET: u64 = 4_096;

/// Floor for the socket budget so scanning still works under a tiny fd limit.
const MIN_SOCKET_BUDGET: u64 = 32;

/// Current `(soft, hard)` open-file limits, if the platform has them.
#[cfg(unix)]
// `rlim_t` is u64 on most targets but a 32-bit `c_ulong` on some; the casts widen there.
#[allow(clippy::unnecessary_cast)]
fn open_file_limits() -> Option<(u64, u64)> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes to the rlimit struct we pass.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0;
    ok.then_some((rl.rlim_cur as u64, rl.rlim_max as u64))
}

#[cfg(not(unix))]
fn open_file_limits() -> Option<(u64, u64)> {
    None
}

/// Raise the soft open-file limit toward [`TARGET_OPEN_FILES`]. Returns the effective soft
/// limit, or `None` where the platform has no such limit (Windows) or it could not be read.
pub fn raise_open_file_limit() -> Option<u64> {
    let (soft, hard) = open_file_limits()?;
    let target = TARGET_OPEN_FILES.min(hard);
    if soft >= target {
        return Some(soft);
    }

    #[cfg(unix)]
    {
        let wanted = libc::rlimit {
            rlim_cur: target as libc::rlim_t,
            rlim_max: hard as libc::rlim_t,
        };
        // SAFETY: setrlimit only reads from the rlimit struct we pass.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &wanted) } == 0 {
            return Some(target);
        }
    }
    Some(soft)
}

/// Number of TCP connections a scan may have in flight at once.
pub fn socket_budget() -> usize {
    let budget = match open_file_limits() {
        Some((soft, _)) => soft.saturating_sub(RESERVED_FDS),
        None => MAX_SOCKET_BUDGET,
    };
    budget.clamp(MIN_SOCKET_BUDGET, MAX_SOCKET_BUDGET) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_budget_is_within_bounds() {
        let budget = socket_budget() as u64;
        assert!((MIN_SOCKET_BUDGET..=MAX_SOCKET_BUDGET).contains(&budget));
    }

    #[test]
    fn raising_the_limit_never_lowers_it() {
        let before = open_file_limits().map(|(soft, _)| soft);
        let after = raise_open_file_limit();
        if let (Some(before), Some(after)) = (before, after) {
            assert!(after >= before);
        }
    }
}
