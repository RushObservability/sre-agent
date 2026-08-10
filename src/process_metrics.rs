//! Portable process and Tokio runtime gauges for the agent.

use crate::metrics::{AgentMetrics, ProcessRuntimeSample};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn spawn(metrics: Arc<AgentMetrics>) {
    tokio::spawn(async move {
        let interval_secs = std::env::var("SRE_AGENT_RUNTIME_METRICS_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value >= 1)
            .unwrap_or(15);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            sample(&metrics);
        }
    });
}

pub fn sample(metrics: &AgentMetrics) {
    let (cpu_seconds, max_resident_memory_bytes) = resource_usage();
    let resident_memory_bytes = current_resident_memory(max_resident_memory_bytes);
    let runtime = tokio::runtime::Handle::current().metrics();
    metrics.set_process_runtime(ProcessRuntimeSample {
        resident_memory_bytes,
        max_resident_memory_bytes,
        cpu_seconds,
        open_fds: proc_count("/proc/self/fd"),
        threads: proc_threads(),
        start_time_seconds: process_start_time_seconds(),
        workers: runtime.num_workers() as u64,
        alive_tasks: runtime.num_alive_tasks() as u64,
    });
}

fn process_start_time_seconds() -> f64 {
    static START: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *START.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs_f64())
            .unwrap_or(0.0)
    })
}

fn current_resident_memory(fallback: u64) -> u64 {
    #[cfg(target_os = "linux")]
    {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size > 0 {
            if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
                if let Some(pages) = statm
                    .split_whitespace()
                    .nth(1)
                    .and_then(|value| value.parse::<u64>().ok())
                {
                    return pages.saturating_mul(page_size as u64);
                }
            }
        }
    }
    fallback
}

fn proc_count(path: &str) -> u64 {
    std::fs::read_dir(path)
        .map(|entries| entries.filter_map(Result::ok).count() as u64)
        .unwrap_or(0)
}

fn proc_threads() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Threads:")
                    .and_then(|value| value.trim().parse::<u64>().ok())
            })
        })
        .unwrap_or(0)
}

#[cfg(unix)]
fn resource_usage() -> (f64, u64) {
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return (0.0, 0);
    }
    let cpu = timeval_seconds(usage.ru_utime) + timeval_seconds(usage.ru_stime);
    let peak = if cfg!(target_os = "macos") {
        usage.ru_maxrss.max(0) as u64
    } else {
        (usage.ru_maxrss.max(0) as u64).saturating_mul(1024)
    };
    (cpu, peak)
}

#[cfg(not(unix))]
fn resource_usage() -> (f64, u64) {
    (0.0, 0)
}

#[cfg(unix)]
fn timeval_seconds(value: libc::timeval) -> f64 {
    value.tv_sec as f64 + value.tv_usec as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_sample_has_a_start_time() {
        let (cpu, _) = resource_usage();
        assert!(cpu.is_finite());
        assert!(process_start_time_seconds() > 0.0);
    }
}
