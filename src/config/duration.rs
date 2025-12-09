use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use std::time::Duration as StdDuration;

/// A duration type that can be deserialized from Go-style duration strings.
/// Supports: "300ms", "1.5s", "2m", "1h30m", "24h"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Duration(StdDuration);

impl Duration {
    pub const ZERO: Duration = Duration(StdDuration::ZERO);

    pub fn from_millis(millis: u64) -> Self {
        Duration(StdDuration::from_millis(millis))
    }

    pub fn from_secs(secs: u64) -> Self {
        Duration(StdDuration::from_secs(secs))
    }

    pub fn as_millis(&self) -> u128 {
        self.0.as_millis()
    }

    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    pub fn as_std(&self) -> StdDuration {
        self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl From<StdDuration> for Duration {
    fn from(d: StdDuration) -> Self {
        Duration(d)
    }
}

impl From<Duration> for StdDuration {
    fn from(d: Duration) -> Self {
        d.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDurationError(String);

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid duration: {}", self.0)
    }
}

impl std::error::Error for ParseDurationError {}

impl FromStr for Duration {
    type Err = ParseDurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_go_duration(s).map(Duration)
    }
}

/// Parse a Go-style duration string.
/// Supports: ns, us (or µs), ms, s, m, h
/// Examples: "300ms", "1.5s", "2m", "1h30m5s", "24h"
fn parse_go_duration(s: &str) -> Result<StdDuration, ParseDurationError> {
    let s = s.trim();

    if s.is_empty() {
        return Err(ParseDurationError("empty string".to_string()));
    }

    if s == "0" {
        return Ok(StdDuration::ZERO);
    }

    let mut total_nanos: u128 = 0;
    let mut remaining = s;

    while !remaining.is_empty() {
        // Find the end of the number part (including optional decimal point)
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(remaining.len());

        if num_end == 0 {
            return Err(ParseDurationError(format!(
                "invalid duration format: {}",
                s
            )));
        }

        let num_str = &remaining[..num_end];
        remaining = &remaining[num_end..];

        // Find the end of the unit part
        let unit_end = remaining
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(remaining.len());

        if unit_end == 0 {
            return Err(ParseDurationError(format!("missing unit in: {}", s)));
        }

        let unit = &remaining[..unit_end];
        remaining = &remaining[unit_end..];

        // Parse the number
        let value: f64 = num_str
            .parse()
            .map_err(|_| ParseDurationError(format!("invalid number: {}", num_str)))?;

        // Convert to nanoseconds based on unit
        let nanos_per_unit: u128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 60 * 60 * 1_000_000_000,
            _ => {
                return Err(ParseDurationError(format!("unknown unit: {}", unit)));
            }
        };

        total_nanos += (value * nanos_per_unit as f64) as u128;
    }

    // Convert nanoseconds to Duration
    let secs = (total_nanos / 1_000_000_000) as u64;
    let nanos = (total_nanos % 1_000_000_000) as u32;

    Ok(StdDuration::new(secs, nanos))
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_nanos = self.0.as_nanos();

        if total_nanos == 0 {
            return write!(f, "0s");
        }

        let hours = total_nanos / (60 * 60 * 1_000_000_000);
        let remaining = total_nanos % (60 * 60 * 1_000_000_000);
        let minutes = remaining / (60 * 1_000_000_000);
        let remaining = remaining % (60 * 1_000_000_000);
        let seconds = remaining / 1_000_000_000;
        let remaining = remaining % 1_000_000_000;
        let millis = remaining / 1_000_000;
        let remaining = remaining % 1_000_000;
        let micros = remaining / 1_000;
        let nanos = remaining % 1_000;

        let mut written = false;

        if hours > 0 {
            write!(f, "{}h", hours)?;
            written = true;
        }
        if minutes > 0 {
            write!(f, "{}m", minutes)?;
            written = true;
        }
        if seconds > 0 || (!written && millis == 0 && micros == 0 && nanos == 0) {
            write!(f, "{}s", seconds)?;
            written = true;
        }
        if millis > 0 && !written {
            write!(f, "{}ms", millis)?;
            written = true;
        }
        if micros > 0 && !written {
            write!(f, "{}us", micros)?;
            written = true;
        }
        if nanos > 0 && !written {
            write!(f, "{}ns", nanos)?;
        }

        Ok(())
    }
}

impl Serialize for Duration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DurationVisitor;

        impl<'de> de::Visitor<'de> for DurationVisitor {
            type Value = Duration;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a duration string like '10s', '1m30s', '100ms'")
            }

            fn visit_str<E>(self, value: &str) -> Result<Duration, E>
            where
                E: de::Error,
            {
                value.parse().map_err(de::Error::custom)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Duration, E>
            where
                E: de::Error,
            {
                if value < 0 {
                    return Err(de::Error::custom("duration cannot be negative"));
                }
                // Assume integer values are in seconds for compatibility
                Ok(Duration::from_secs(value as u64))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Duration, E>
            where
                E: de::Error,
            {
                // Assume integer values are in seconds for compatibility
                Ok(Duration::from_secs(value))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Duration, E>
            where
                E: de::Error,
            {
                if value < 0.0 {
                    return Err(de::Error::custom("duration cannot be negative"));
                }
                // Assume float values are in seconds
                Ok(Duration::from_millis((value * 1000.0) as u64))
            }
        }

        deserializer.deserialize_any(DurationVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        assert_eq!(
            "100ms".parse::<Duration>().unwrap().as_millis(),
            100
        );
        assert_eq!("10s".parse::<Duration>().unwrap().as_secs(), 10);
        assert_eq!("5m".parse::<Duration>().unwrap().as_secs(), 300);
        assert_eq!("2h".parse::<Duration>().unwrap().as_secs(), 7200);
    }

    #[test]
    fn test_parse_compound() {
        assert_eq!(
            "1h30m".parse::<Duration>().unwrap().as_secs(),
            5400
        );
        assert_eq!(
            "1m30s".parse::<Duration>().unwrap().as_secs(),
            90
        );
        assert_eq!(
            "1h30m45s".parse::<Duration>().unwrap().as_secs(),
            5445
        );
    }

    #[test]
    fn test_parse_decimal() {
        assert_eq!(
            "1.5s".parse::<Duration>().unwrap().as_millis(),
            1500
        );
        assert_eq!(
            "0.5m".parse::<Duration>().unwrap().as_secs(),
            30
        );
    }

    #[test]
    fn test_parse_zero() {
        assert_eq!("0".parse::<Duration>().unwrap().as_millis(), 0);
        assert_eq!("0s".parse::<Duration>().unwrap().as_millis(), 0);
    }

    #[test]
    fn test_display() {
        assert_eq!(Duration::from_secs(90).to_string(), "1m30s");
        assert_eq!(Duration::from_secs(3600).to_string(), "1h");
        assert_eq!(Duration::from_millis(100).to_string(), "100ms");
    }
}
