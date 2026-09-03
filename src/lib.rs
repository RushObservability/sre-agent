//! SRE investigation agent library.
//!
//! This crate exposes its modules publicly so integration tests in `tests/`
//! can drive the agent loop with mock LLMs, fake tools, and in-memory config.

pub mod agent;
pub mod cancellation;
pub mod http;
pub mod metrics;
pub mod models;
pub mod process_metrics;
pub mod query_api;
pub mod repository;
pub mod state;

pub use state::AppState;
