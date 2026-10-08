//! The syslog header a collector may have put before a firewall's message:
//! an octet count (RFC 6587 framing), a priority (`<14>`), then RFC 5424's
//! `1 2024-02-22T12:32:26-05:00 HOST APP PROCID MSGID SD`, a bare ISO 8601
//! time and host, or RFC 3164's `Sep 14 23:42:50 HOST`. All are optional.

use common::time::Ts;

use crate::time;

/// What a header said, and the message after it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Header<'a> {
    /// The header's time as written.
    pub stamp: Option<&'a str>,
    /// That time, when it has a year and a zone (RFC 5424, ISO 8601).
    pub time: Option<Ts>,
    /// The sending host.
    pub host: Option<&'a str>,
    /// What follows the header.
    pub body: &'a str,
}

/// `line`'s header, if any, and its message.
pub(crate) fn split(line: &str) -> Header<'_> {
    let rest = skip_priority(skip_octet_count(line.trim_start()));
    rfc5424(rest)
        .or_else(|| iso(rest))
        .or_else(|| rfc3164(rest))
        .unwrap_or(Header {
            body: rest,
            ..Header::default()
        })
}

/// `671 <14>…`: a message length before the priority.
fn skip_octet_count(text: &str) -> &str {
    match text.split_once(' ') {
        Some((count, rest))
            if !count.is_empty()
                && count.bytes().all(|b| b.is_ascii_digit())
                && rest.starts_with('<') =>
        {
            rest
        }
        _ => text,
    }
}

/// `<190>`.
fn skip_priority(text: &str) -> &str {
    text.strip_prefix('<')
        .and_then(|rest| rest.split_once('>'))
        .filter(|(priority, _)| {
            (1..=3).contains(&priority.len()) && priority.bytes().all(|b| b.is_ascii_digit())
        })
        .map_or(text, |(_, rest)| rest)
}

/// `1 TIMESTAMP HOST APP PROCID MSGID SD MSG`, `-` for what is absent.
fn rfc5424(text: &str) -> Option<Header<'_>> {
    let (version, rest) = text.split_once(' ')?;
    if !(1..=2).contains(&version.len()) || !version.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (stamp, rest) = rest.split_once(' ')?;
    let time = time::iso8601(stamp);
    if stamp != "-" && time.is_none() {
        return None;
    }
    let (host, rest) = rest.split_once(' ')?;
    let (_app, rest) = rest.split_once(' ')?;
    let (_process, rest) = rest.split_once(' ')?;
    let (_message_id, rest) = rest.split_once(' ')?;
    let body = skip_structured_data(rest)?;
    Some(Header {
        stamp: present(stamp),
        time,
        host: present(host),
        body: body.strip_prefix(' ').unwrap_or(body),
    })
}

/// `-`, or `[id name="value" …]` elements, `\]` escaped inside.
fn skip_structured_data(text: &str) -> Option<&str> {
    if let Some(rest) = text.strip_prefix('-') {
        return Some(rest);
    }
    let mut rest = text;
    while let Some(inside) = rest.strip_prefix('[') {
        let mut escaped = false;
        let end = inside.char_indices().find_map(|(at, c)| {
            let closes = c == ']' && !escaped;
            escaped = c == '\\' && !escaped;
            closes.then_some(at)
        })?;
        rest = inside.get(end + 1..)?;
    }
    (rest.len() < text.len()).then_some(rest)
}

/// `2024-02-22T12:32:26-05:00 HOST MSG`, as some collectors write.
fn iso(text: &str) -> Option<Header<'_>> {
    let (stamp, rest) = text.split_once(' ')?;
    let time = time::iso8601(stamp)?;
    let (host, body) = host_and_body(rest)?;
    Some(Header {
        stamp: Some(stamp),
        time: Some(time),
        host: Some(host),
        body,
    })
}

/// `Sep 14 23:42:50 HOST MSG` (`Nov  7` padded): no year, so no time.
fn rfc3164(text: &str) -> Option<Header<'_>> {
    let (month, rest) = text.split_once(' ')?;
    let rest = rest.trim_start_matches(' ');
    let (day, rest) = rest.split_once(' ')?;
    let (clock, rest) = rest.split_once(' ')?;
    let is_day = (1..=2).contains(&day.len()) && day.bytes().all(|b| b.is_ascii_digit());
    if !time::is_month(month) || !is_day || !time::is_clock(clock) {
        return None;
    }
    let stamp_length = text.len() - rest.len() - 1;
    let (host, body) = host_and_body(rest)?;
    Some(Header {
        stamp: text.get(..stamp_length),
        time: None,
        host: Some(host),
        body,
    })
}

/// A host name, then the message; a word with a comma or a colon at
/// either end is the message's, not a host.
fn host_and_body(text: &str) -> Option<(&str, &str)> {
    let (host, body) = text.split_once(' ').unwrap_or((text, ""));
    let is_host = !host.is_empty()
        && !host.contains(',')
        && !host.contains('=')
        && !host.starts_with(':')
        && !host.ends_with(':');
    is_host.then_some((host, body))
}

/// `-` means absent.
fn present(text: &str) -> Option<&str> {
    (text != "-" && !text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        let h = split("671 <14>1 2024-02-22T12:32:26-05:00 PALO220 - - - - 1,2024/02/22");
        assert_eq!(h.host, Some("PALO220"));
        assert_eq!(h.stamp, Some("2024-02-22T12:32:26-05:00"));
        assert!(h.time.is_some());
        assert_eq!(h.body, "1,2024/02/22");

        let h = split("<190>Nov  7 09:07:15 firewall.logs 1,2024/11/07 09:07:14");
        assert_eq!(h.stamp, Some("Nov  7 09:07:15"));
        assert_eq!(h.host, Some("firewall.logs"));
        assert_eq!(h.body, "1,2024/11/07 09:07:14");

        let h = split(r#"<134>1 - fw app - - [x a="\]\""][y] date=2024-01-05"#);
        assert_eq!(h.host, Some("fw"));
        assert_eq!(h.body, "date=2024-01-05");

        let h = split("Sep 23 18:13:32 192.0.2.1 :2025-09-23T18:13:31Z: %ASA-7-111009: x");
        assert_eq!(h.host, Some("192.0.2.1"));

        let h = split("date=2024-01-05 time=10:22:33");
        assert_eq!(
            h,
            Header {
                body: "date=2024-01-05 time=10:22:33",
                ..Header::default()
            }
        );
    }
}
