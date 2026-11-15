//! Server-side stream delivery latency and bounded channel backpressure.
use super::{AgentMetrics, HISTOGRAM_BUCKETS, Histogram};
use crate::agent::stream::AgentEvent;
use std::{
    collections::BTreeMap,
    fmt::Write,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::mpsc;
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Channel {
    Agent,
    Client,
}
impl Channel {
    fn label(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Client => "client",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SendOutcome {
    Sent,
    Closed,
    Cancelled,
}
impl SendOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Closed => "closed",
            Self::Cancelled => "cancelled",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FirstEvent {
    Thinking,
    Tool,
    Summary,
}
impl FirstEvent {
    fn label(self) -> &'static str {
        match self {
            Self::Thinking => "thinking",
            Self::Tool => "tool",
            Self::Summary => "summary",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Terminal {
    Completed,
    Disconnected,
    Error,
}
impl Terminal {
    fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Disconnected => "disconnected",
            Self::Error => "error",
        }
    }
}
#[derive(Default)]
pub(super) struct StreamingMetrics {
    send_wait: Mutex<BTreeMap<Channel, Histogram>>,
    sends: Mutex<BTreeMap<(Channel, SendOutcome), u64>>,
    first_event: Mutex<BTreeMap<FirstEvent, Histogram>>,
    terminals: Mutex<BTreeMap<Terminal, u64>>,
}
fn render_histogram(out: &mut String, name: &str, label: &str, value: &str, h: &Histogram) {
    for (i, b) in HISTOGRAM_BUCKETS.iter().enumerate() {
        let _ = writeln!(
            out,
            "{name}_bucket{{{label}=\"{value}\",le=\"{b}\"}} {}",
            h.buckets[i]
        );
    }
    let _ = writeln!(
        out,
        "{name}_bucket{{{label}=\"{value}\",le=\"+Inf\"}} {}\n{name}_sum{{{label}=\"{value}\"}} {}\n{name}_count{{{label}=\"{value}\"}} {}",
        h.count, h.sum, h.count
    );
}
impl StreamingMetrics {
    pub(super) fn render(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# TYPE sre_agent_event_send_wait_seconds histogram\n# TYPE sre_agent_event_sends_total counter\n# TYPE sre_agent_time_to_first_event_seconds histogram\n# TYPE sre_agent_sse_terminal_total counter"
        );
        for (channel, h) in self
            .send_wait
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            render_histogram(
                out,
                "sre_agent_event_send_wait_seconds",
                "channel",
                channel.label(),
                h,
            );
        }
        for ((channel, outcome), count) in
            self.sends.lock().unwrap_or_else(|e| e.into_inner()).iter()
        {
            let _ = writeln!(
                out,
                "sre_agent_event_sends_total{{channel=\"{}\",outcome=\"{}\"}} {count}",
                channel.label(),
                outcome.label()
            );
        }
        for (event, h) in self
            .first_event
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            render_histogram(
                out,
                "sre_agent_time_to_first_event_seconds",
                "event",
                event.label(),
                h,
            );
        }
        for (reason, count) in self
            .terminals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            let _ = writeln!(
                out,
                "sre_agent_sse_terminal_total{{reason=\"{}\"}} {count}",
                reason.label()
            );
        }
    }
}
struct SendGuard<'a> {
    metrics: Option<&'a AgentMetrics>,
    channel: Channel,
    started: Instant,
    outcome: SendOutcome,
}
impl Drop for SendGuard<'_> {
    fn drop(&mut self) {
        if let Some(metrics) = self.metrics {
            metrics
                .streaming
                .send_wait
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(self.channel)
                .or_default()
                .observe(self.started.elapsed().as_secs_f64());
            *metrics
                .streaming
                .sends
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry((self.channel, self.outcome))
                .or_default() += 1;
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) struct EventSender<'a> {
    sender: &'a mpsc::Sender<AgentEvent>,
    metrics: Option<&'a AgentMetrics>,
    channel: Channel,
}
impl<'a> EventSender<'a> {
    pub(crate) fn new(
        sender: &'a mpsc::Sender<AgentEvent>,
        metrics: &'a Arc<AgentMetrics>,
        channel: Channel,
    ) -> Self {
        Self {
            sender,
            metrics: Some(metrics),
            channel,
        }
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
    pub(crate) async fn send(
        &self,
        event: AgentEvent,
    ) -> Result<(), mpsc::error::SendError<AgentEvent>> {
        let mut guard = SendGuard {
            metrics: self.metrics,
            channel: self.channel,
            started: Instant::now(),
            outcome: SendOutcome::Cancelled,
        };
        let result = self.sender.send(event).await;
        guard.outcome = if result.is_ok() {
            SendOutcome::Sent
        } else {
            SendOutcome::Closed
        };
        result
    }
}
impl<'a> From<&'a mpsc::Sender<AgentEvent>> for EventSender<'a> {
    fn from(sender: &'a mpsc::Sender<AgentEvent>) -> Self {
        Self {
            sender,
            metrics: None,
            channel: Channel::Agent,
        }
    }
}
pub(crate) struct StreamObservation {
    metrics: Arc<AgentMetrics>,
    started: Instant,
    first_observed: bool,
    terminal: Option<Terminal>,
}
impl StreamObservation {
    pub(crate) fn new(metrics: Arc<AgentMetrics>, started: Instant) -> Self {
        Self {
            metrics,
            started,
            first_observed: false,
            terminal: None,
        }
    }
    pub(crate) fn observe(&mut self, event: &AgentEvent) {
        if !self.first_observed {
            let first = match event {
                AgentEvent::ThinkingDelta { text } if !text.is_empty() => {
                    Some(FirstEvent::Thinking)
                }
                AgentEvent::ToolCall { .. } | AgentEvent::ToolResult { .. } => {
                    Some(FirstEvent::Tool)
                }
                AgentEvent::Summary { text, .. } if !text.is_empty() => Some(FirstEvent::Summary),
                _ => None,
            };
            if let Some(first) = first {
                self.first_observed = true;
                self.metrics
                    .streaming
                    .first_event
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(first)
                    .or_default()
                    .observe(self.started.elapsed().as_secs_f64());
            }
        }
        match event {
            AgentEvent::Error { .. } => self.terminal = Some(Terminal::Error),
            AgentEvent::Done { .. } if self.terminal.is_none() => {
                self.terminal = Some(Terminal::Completed)
            }
            _ => {}
        }
    }
    pub(crate) fn channel_closed(&mut self) {
        if self.terminal.is_none() {
            self.terminal = Some(Terminal::Error);
        }
    }
}
impl Drop for StreamObservation {
    fn drop(&mut self) {
        *self
            .metrics
            .streaming
            .terminals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(self.terminal.unwrap_or(Terminal::Disconnected))
            .or_default() += 1;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn send_wait_accounts_for_backpressure_closed_receivers_and_cancelled_sends() {
        let metrics = Arc::new(AgentMetrics::new());
        let (tx, mut rx) = mpsc::channel(1);
        let event = || AgentEvent::ThinkingDelta {
            text: "sensitive-content".into(),
        };
        tx.send(event()).await.unwrap();
        let measured = EventSender::new(&tx, &metrics, Channel::Agent);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), measured.send(event()))
                .await
                .is_err()
        );
        rx.recv().await.unwrap();
        measured.send(event()).await.unwrap();
        drop(rx);
        assert!(measured.send(event()).await.is_err());
        let out = metrics.render();
        for outcome in ["cancelled", "sent", "closed"] {
            assert!(out.contains(&format!(
                "sre_agent_event_sends_total{{channel=\"agent\",outcome=\"{outcome}\"}} 1"
            )));
        }
        assert!(out.contains("sre_agent_event_send_wait_seconds_count{channel=\"agent\"} 3"));
        assert!(!out.contains("sensitive"));
    }
}
