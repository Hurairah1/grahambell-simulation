//! UTC timestamps without a date-time dependency.
//!
//! Converts Unix seconds to a civil UTC date with Howard Hinnant's `civil_from_days`
//! algorithm, which is exact for the proleptic Gregorian calendar.

use std::time::{SystemTime, UNIX_EPOCH};

/// A UTC date and time, to the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcTimestamp {
    /// Year.
    pub year: i64,
    /// Month, 1–12.
    pub month: u32,
    /// Day of month, 1–31.
    pub day: u32,
    /// Hour, 0–23.
    pub hour: u32,
    /// Minute, 0–59.
    pub minute: u32,
    /// Second, 0–59.
    pub second: u32,
}

impl UtcTimestamp {
    /// The current time. A clock set before 1970 is treated as the Unix epoch.
    pub fn now() -> UtcTimestamp {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        UtcTimestamp::from_unix_seconds(i64::try_from(seconds).unwrap_or(i64::MAX))
    }

    /// The UTC time `seconds` after 1970-01-01T00:00:00Z.
    pub fn from_unix_seconds(seconds: i64) -> UtcTimestamp {
        let days = seconds.div_euclid(86_400);
        let second_of_day = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        // `second_of_day` is in 0..86_400, so these narrowing conversions are exact.
        let hour = (second_of_day / 3_600) as u32;
        let minute = ((second_of_day % 3_600) / 60) as u32;
        let second = (second_of_day % 60) as u32;
        UtcTimestamp {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    /// RFC 3339 form, for example `2026-10-05T13:32:00Z`.
    pub fn rfc3339(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// Compact form used in run ids, for example `20261005T133200Z`.
    pub fn compact(&self) -> String {
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Year, month and day of the date `days` after 1970-01-01 (Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    // Both values are small and non-negative by construction of the algorithm.
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_is_1970_01_01() {
        assert_eq!(
            UtcTimestamp::from_unix_seconds(0).rfc3339(),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn known_timestamp_converts_exactly() {
        // 2026-10-05T13:32:00Z, checked against `date -u -r 1791207120`.
        let t = UtcTimestamp::from_unix_seconds(1_791_207_120);
        assert_eq!(t.rfc3339(), "2026-10-05T13:32:00Z");
        assert_eq!(t.compact(), "20261005T133200Z");
    }

    #[test]
    fn leap_day_2024_is_handled() {
        // 2024-02-29T23:59:59Z.
        let t = UtcTimestamp::from_unix_seconds(1_709_251_199);
        assert_eq!(t.rfc3339(), "2024-02-29T23:59:59Z");
    }

    #[test]
    fn year_2000_century_leap_year_is_handled() {
        // 2000-03-01T00:00:00Z follows 2000-02-29.
        assert_eq!(
            UtcTimestamp::from_unix_seconds(951_868_800).rfc3339(),
            "2000-03-01T00:00:00Z"
        );
    }

    #[test]
    fn times_before_the_epoch_are_supported() {
        assert_eq!(
            UtcTimestamp::from_unix_seconds(-1).rfc3339(),
            "1969-12-31T23:59:59Z"
        );
    }

    #[test]
    fn now_is_after_the_project_start() {
        assert!(UtcTimestamp::now().year >= 2026);
    }
}
