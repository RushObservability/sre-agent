#![no_main]

use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;
#[path = "../../src/timestamps.rs"]
mod timestamps;

use timestamps::format_nanos_timestamp;

fuzz_target!(|nanos: i64| {
    let formatted = format_nanos_timestamp(nanos);
    let timestamp = formatted
        .parse::<Timestamp>()
        .expect("valid RFC 3339 output");
    assert_eq!(timestamp.as_nanosecond(), i128::from(nanos));
});
