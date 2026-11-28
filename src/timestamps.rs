//! Formats shared with the query API and the offline evaluation tools.

use jiff::Timestamp;

pub trait TimestampFormat {
    /// Format an RFC 3339 UTC timestamp with the existing 3/6/9 digit precision.
    fn to_rfc3339(self) -> String;
}

impl TimestampFormat for Timestamp {
    fn to_rfc3339(self) -> String {
        let nanos = self.subsec_nanosecond();
        let format = if nanos == 0 {
            "%Y-%m-%dT%H:%M:%S+00:00"
        } else if nanos % 1_000_000 == 0 {
            "%Y-%m-%dT%H:%M:%S%.3f+00:00"
        } else if nanos % 1_000 == 0 {
            "%Y-%m-%dT%H:%M:%S%.6f+00:00"
        } else {
            "%Y-%m-%dT%H:%M:%S%.9f+00:00"
        };
        self.strftime(format).to_string()
    }
}

pub fn format_nanos_timestamp(nanos: i64) -> String {
    Timestamp::from_nanosecond(i128::from(nanos))
        .map(TimestampFormat::to_rfc3339)
        .unwrap_or_else(|_| nanos.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_keeps_existing_fractional_precision() {
        for (nanos, expected) in [
            (0, "1970-01-01T00:00:00+00:00"),
            (120_000_000, "1970-01-01T00:00:00.120+00:00"),
            (123_450_000, "1970-01-01T00:00:00.123450+00:00"),
            (123_456_780, "1970-01-01T00:00:00.123456780+00:00"),
            (-1, "1969-12-31T23:59:59.999999999+00:00"),
        ] {
            let timestamp = Timestamp::from_nanosecond(nanos).unwrap();
            assert_eq!(timestamp.to_rfc3339(), expected);
        }
    }
}
