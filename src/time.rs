//! The times firewalls write: ISO 8601 with a zone (PAN-OS's high
//! resolution timestamp, RFC 5424 headers, the ASA's `logging timestamp
//! rfc5424`), local dates and clocks (PAN-OS's `2024/02/22 12:32:26`,
//! FortiGate's `date` and `time`, the ASA's `Oct 30 2025 11:04:10`), and
//! FortiGate's `eventtime` since 1970 in seconds, milliseconds,
//! microseconds or nanoseconds.

use common::time::{civil_from_days, days_from_civil, Precision, Ts};

const TICKS_PER_SECOND: i64 = 10_000_000;

/// Month abbreviations, as syslog and the ASA write them.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `2023-09-14T23:42:50.344+00:00`, `2025-09-23T18:13:31Z`: UTC; with no
/// zone, local.
pub(crate) fn iso8601(text: &str) -> Option<Ts> {
    let (date, rest) = text.trim().split_once(['T', 't'])?;
    let (year, month, day) = date_parts(date, '-')?;
    let zone_at = rest.find(['Z', 'z', '+', '-']).unwrap_or(rest.len());
    let (clock, zone) = rest.split_at(zone_at);
    let (whole, fraction) = clock.split_once('.').unwrap_or((clock, ""));
    let (hour, minute, second) = clock_parts(whole)?;
    let (sub, precision) = fraction_ticks(fraction)?;
    let ticks = wall_ticks(year, month, day, hour, minute, second)? + sub;
    let local = Ts::from_local_ticks(ticks, precision);
    if zone.is_empty() {
        return Some(local);
    }
    Some(local.assume_offset(offset_minutes(zone)?)).filter(|t| t.ticks().is_some())
}

/// `2024/02/22 12:32:26` (PAN-OS): local, to the second.
pub(crate) fn slashed(text: &str) -> Option<Ts> {
    let (date, clock) = text.trim().split_once(' ')?;
    let (year, month, day) = date_parts(date, '/')?;
    local(year, month, day, clock)
}

/// `2024-01-05` and `10:22:33` (FortiGate): local, to the second.
pub(crate) fn dashed(date: &str, clock: &str) -> Option<Ts> {
    let (year, month, day) = date_parts(date.trim(), '-')?;
    local(year, month, day, clock.trim())
}

/// `Oct`, `30`, `2025` and `11:04:10` (the ASA's own timestamp): local,
/// to the second.
pub(crate) fn named_month(month: &str, day: &str, year: &str, clock: &str) -> Option<Ts> {
    let month = MONTHS.iter().position(|m| *m == month)? as u32 + 1;
    local(
        number(year, 4..=4)?,
        month,
        number(day, 1..=2)? as u32,
        clock,
    )
}

/// Whether `word` is a month abbreviation (`Sep`).
pub(crate) fn is_month(word: &str) -> bool {
    MONTHS.contains(&word)
}

/// Whether `text` is a clock (`23:42:50`).
pub(crate) fn is_clock(text: &str) -> bool {
    clock_parts(text).is_some()
}

/// Seconds, milliseconds, microseconds or nanoseconds since 1970, told
/// apart by magnitude: seconds below 10^11 (the year 5138), milliseconds
/// below 10^14, microseconds below 10^17, nanoseconds above.
pub(crate) fn epoch(text: &str) -> Option<Ts> {
    let value: i64 = text.trim().parse().ok()?;
    let ts = match value.unsigned_abs() {
        0..=99_999_999_999 => Ts::from_unix_seconds(value),
        100_000_000_000..=99_999_999_999_999 => Ts::from_unix_millis(value),
        100_000_000_000_000..=99_999_999_999_999_999 => Ts::from_unix_micros(value),
        _ => Ts::from_unix_nanos(value),
    };
    ts.ticks().map(|_| ts)
}

/// `Z`, `+11:00`, `-0500`, `+01` in minutes east of UTC.
pub(crate) fn offset_minutes(zone: &str) -> Option<i32> {
    let zone = zone.trim();
    if zone.eq_ignore_ascii_case("z") {
        return Some(0);
    }
    let (sign, digits) = match zone.split_at_checked(1)? {
        ("+", rest) => (1, rest),
        ("-", rest) => (-1, rest),
        _ => return None,
    };
    let digits = digits.replacen(':', "", 1);
    let (hours, minutes) = match digits.len() {
        2 => (digits.as_str(), "00"),
        4 => digits.split_at_checked(2)?,
        _ => return None,
    };
    let hours = number(hours, 2..=2)?;
    let minutes = number(minutes, 2..=2)?;
    (hours <= 23 && minutes <= 59).then(|| sign * (hours * 60 + minutes) as i32)
}

/// A local wall-clock time, to the second.
fn local(year: i64, month: u32, day: u32, clock: &str) -> Option<Ts> {
    let (hour, minute, second) = clock_parts(clock)?;
    let ticks = wall_ticks(year, month, day, hour, minute, second)?;
    Some(Ts::from_local_ticks(ticks, Precision::Second))
}

/// `2024-01-05` or `2024/01/05` split at `separator`.
fn date_parts(date: &str, separator: char) -> Option<(i64, u32, u32)> {
    let mut parts = date.split(separator);
    let year = number(parts.next()?, 4..=4)?;
    let month = number(parts.next()?, 1..=2)? as u32;
    let day = number(parts.next()?, 1..=2)? as u32;
    parts.next().is_none().then_some((year, month, day))
}

/// `HH:MM:SS`.
fn clock_parts(clock: &str) -> Option<(i64, i64, i64)> {
    let mut parts = clock.split(':');
    let hour = number(parts.next()?, 1..=2)?;
    let minute = number(parts.next()?, 2..=2)?;
    let second = number(parts.next()?, 2..=2)?;
    parts.next().is_none().then_some((hour, minute, second))
}

/// A fraction of a second as ticks (seven digits kept), and the precision
/// its length gives.
fn fraction_ticks(fraction: &str) -> Option<(i64, Precision)> {
    if fraction.is_empty() {
        return Some((0, Precision::Second));
    }
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let precision = match fraction.len() {
        1..=3 => Precision::Millisecond,
        4..=6 => Precision::Microsecond,
        _ => Precision::Tick,
    };
    let kept: String = fraction.chars().take(7).collect();
    Some((format!("{kept:0<7}").parse().ok()?, precision))
}

/// Ticks since 1970 of a wall-clock time counted as if UTC; `None` for
/// times that don't exist (February 30, 25:00).
fn wall_ticks(year: i64, month: u32, day: u32, hour: i64, minute: i64, second: i64) -> Option<i64> {
    let valid = (1..=9999).contains(&year)
        && (1..=12).contains(&month)
        && (0..24).contains(&hour)
        && (0..60).contains(&minute)
        && (0..=60).contains(&second);
    let days = days_from_civil(year, month, day);
    (valid && civil_from_days(days) == (year, month, day))
        .then(|| (days * 86_400 + hour * 3600 + minute * 60 + second) * TICKS_PER_SECOND)
}

/// Decimal digits, as many as `lengths` allows.
fn number(text: &str, lengths: std::ops::RangeInclusive<usize>) -> Option<i64> {
    (lengths.contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso(t: Option<Ts>) -> Option<String> {
        t.and_then(|t| t.to_iso8601())
    }

    #[test]
    fn zoned() {
        assert_eq!(
            iso(iso8601("2024-11-07T09:07:13.743+11:00")).as_deref(),
            Some("2024-11-06T22:07:13.7430000Z")
        );
        assert_eq!(
            iso(iso8601("2024-02-22T12:32:26-05:00")).as_deref(),
            Some("2024-02-22T17:32:26.0000000Z")
        );
        assert_eq!(
            iso(iso8601("2025-09-23T18:13:31Z")).as_deref(),
            Some("2025-09-23T18:13:31.0000000Z")
        );
        assert_eq!(iso8601("2024-02-30T00:00:00Z"), None);
        assert_eq!(iso8601("2024-02-01T00:00:00+7"), None);
    }

    #[test]
    fn local_times() {
        assert_eq!(
            iso(slashed("2023/09/14 23:42:49")).as_deref(),
            Some("2023-09-14T23:42:49.0000000")
        );
        assert_eq!(
            iso(named_month("Oct", "30", "2025", "11:04:10")).as_deref(),
            Some("2025-10-30T11:04:10.0000000")
        );
        assert_eq!(slashed("2023/13/14 23:42:49"), None);
    }

    #[test]
    fn epochs_by_magnitude() {
        let want = Some("2024-01-05T10:22:33.0000000Z");
        assert_eq!(iso(epoch("1704450153")).as_deref(), want);
        assert_eq!(iso(epoch("1704450153000")).as_deref(), want);
        assert_eq!(iso(epoch("1704450153000000")).as_deref(), want);
        assert_eq!(
            iso(epoch("1704450153123456789")).as_deref(),
            Some("2024-01-05T10:22:33.1234567Z")
        );
        assert_eq!(epoch("0"), None);
        assert_eq!(epoch("soon"), None);
    }

    #[test]
    fn offsets() {
        assert_eq!(offset_minutes("+0100"), Some(60));
        assert_eq!(offset_minutes("-05:30"), Some(-330));
        assert_eq!(offset_minutes("+01"), Some(60));
        assert_eq!(offset_minutes("+2500"), None);
        assert_eq!(offset_minutes("é"), None);
    }
}
