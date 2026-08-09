//! A small cancellation token built from Tokio's existing watch primitive.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::watch;

#[derive(Clone)]
pub struct CancellationToken {
    sender: Arc<watch::Sender<bool>>,
    cancelled_at: Arc<Mutex<Option<Instant>>>,
}

impl CancellationToken {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self {
            sender: Arc::new(sender),
            cancelled_at: Arc::new(Mutex::new(None)),
        }
    }

    pub fn cancel(&self) {
        let mut cancelled_at = self
            .cancelled_at
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if cancelled_at.is_none() {
            *cancelled_at = Some(Instant::now());
        }
        self.sender.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        if *receiver.borrow() {
            return;
        }
        let _ = receiver.changed().await;
    }

    pub fn elapsed_since_cancelled(&self) -> Option<Duration> {
        self.cancelled_at
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .map(|started| started.elapsed())
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::CancellationToken;

    #[tokio::test]
    async fn cancellation_is_observed_by_waiters() {
        let token = CancellationToken::new();
        let waiter = {
            let token = token.clone();
            tokio::spawn(async move {
                token.cancelled().await;
                token.is_cancelled()
            })
        };
        token.cancel();
        assert!(waiter.await.unwrap());
        assert!(token.elapsed_since_cancelled().is_some());
    }
}
