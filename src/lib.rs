//! SRE investigation agent library.
//!
//! This crate exposes its modules publicly so integration tests in `tests/`
//! can drive the agent loop with mock LLMs, fake tools, and in-memory config.

pub mod agent;
pub mod config_db;
pub mod models;
pub mod state;

pub use state::AppState;
