//! Fortinet FortiGate: `key=value` lines, values with spaces quoted (`\"`
//! escaped inside), and the CSV the web interface's log download writes,
//! one `key=value` per cell. The keys are FortiOS's, as its Log Message
//! Reference names them: `type` and `subtype`, `srcip`, `dstport`,
//! `policyid`, `action`, `user`, `msg`, …

use common::time::Ts;

use crate::{csv, syslog, time, Entry, Mapping, Parsed, Vendor};

const MAPPING: Mapping = Mapping {
    action: &["action", "status"],
    source: &["srcip", "remip"],
    source_port: &["srcport"],
    destination: &["dstip"],
    destination_port: &["dstport"],
    protocol: &["proto"],
    user: &["user", "unauthuser"],
    application: &["app", "service"],
    rule: &["policyname", "policyid"],
    device: &["devname", "devid", "sysloghost"],
    message: &["msg", "logdesc"],
};

/// A line with a `logid`, or a `type` and a device's name or id.
pub(crate) fn read(line: &str) -> Option<Result<Parsed, String>> {
    let header = syslog::split(line);
    let pairs = pairs(header.body);
    let has = |key: &str| pairs.iter().any(|(k, _)| k == key);
    if !(has("logid") || (has("type") && (has("devname") || has("devid")))) {
        return None;
    }
    let mut entry = Entry::new(Vendor::Fortinet, &header);
    for (key, value) in &pairs {
        entry.put(key, value);
    }
    entry.kind = match (entry.get("type"), entry.get("subtype")) {
        (Some(log_type), Some(subtype)) => Some(format!("{log_type}/{subtype}")),
        (log_type, _) => log_type.map(str::to_owned),
    };
    let (time, damage) = entry_time(&entry);
    entry.time = time.or(header.time);
    entry.fill(&MAPPING);
    Some(Ok(Parsed { entry, damage }))
}

/// `eventtime` since 1970, else `date` and `time` with `tz` applied (local
/// without it); and which of them couldn't be read.
fn entry_time(entry: &Entry) -> (Option<Ts>, Option<String>) {
    let mut damage = None;
    if let Some(text) = entry.get("eventtime") {
        match time::epoch(text) {
            Some(time) => return (Some(time), None),
            None => damage = Some(format!("eventtime {text:?} not read")),
        }
    }
    let (Some(date), Some(clock)) = (entry.get("date"), entry.get("time")) else {
        return (None, damage);
    };
    let Some(local) = time::dashed(date, clock) else {
        return (
            None,
            Some(format!("date and time {date:?} {clock:?} not read")),
        );
    };
    let zoned = entry
        .get("tz")
        .and_then(time::offset_minutes)
        .map_or(local, |offset| local.assume_offset(offset));
    (Some(zoned), damage)
}

/// A message's pairs: CSV when it starts with a quoted cell or its first
/// pair ends at a comma.
fn pairs(body: &str) -> Vec<(String, String)> {
    let mut first = Pairs { rest: body };
    first.next();
    if body.trim_start().starts_with('"') || first.rest.starts_with(',') {
        csv::cells(body)
            .iter()
            .filter_map(|cell| cell_pair(cell))
            .collect()
    } else {
        Pairs { rest: body }.collect()
    }
}

/// A CSV cell's `key=value`, the value unquoted.
fn cell_pair(cell: &str) -> Option<(String, String)> {
    let (key, value) = cell.split_once('=')?;
    let key = key.trim();
    let value = value.trim();
    let value = match value.strip_prefix('"') {
        Some(inside) => quoted(inside).0,
        None => value.to_owned(),
    };
    (!key.is_empty()).then(|| (key.to_owned(), value))
}

/// `key=value` pairs between spaces (or commas): a quoted value runs to its
/// closing quote, a bare one to a space or comma; words without `=` are
/// skipped.
struct Pairs<'a> {
    rest: &'a str,
}

impl Iterator for Pairs<'_> {
    type Item = (String, String);

    fn next(&mut self) -> Option<Self::Item> {
        let is_separator = |c: char| c.is_whitespace() || c == ',';
        loop {
            let text = self.rest.trim_start_matches(is_separator);
            if text.is_empty() {
                self.rest = text;
                return None;
            }
            let end = text
                .find(|c: char| c == '=' || is_separator(c))
                .unwrap_or(text.len());
            let (key, after) = text.split_at(end);
            let Some(after) = after.strip_prefix('=') else {
                self.rest = after;
                continue;
            };
            let (value, rest) = if let Some(inside) = after.strip_prefix('"') {
                quoted(inside)
            } else {
                let end = after.find(is_separator).unwrap_or(after.len());
                let (value, rest) = after.split_at(end);
                (value.to_owned(), rest)
            };
            self.rest = rest;
            if !key.is_empty() {
                return Some((key.to_owned(), value));
            }
        }
    }
}

/// A quoted value, from after its opening quote to its closing one (`\"`
/// and `\\` escaped), and what follows; unclosed, all of it.
fn quoted(text: &str) -> (String, &str) {
    let mut value = String::new();
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match c {
            '\\' if matches!(chars.peek(), Some((_, '"' | '\\'))) => {
                if let Some((_, escaped)) = chars.next() {
                    value.push(escaped);
                }
            }
            '"' => return (value, text.get(at + 1..).unwrap_or_default()),
            c => value.push(c),
        }
    }
    (value, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(key: &str, value: &str) -> (String, String) {
        (key.to_owned(), value.to_owned())
    }

    #[test]
    fn key_values() {
        let got = pairs(r#"date=2024-01-05 devname="FG 100" msg="say \"hi\"" x  srcip=192.0.2.1"#);
        assert_eq!(
            got,
            [
                pair("date", "2024-01-05"),
                pair("devname", "FG 100"),
                pair("msg", "say \"hi\""),
                pair("srcip", "192.0.2.1"),
            ]
        );
    }

    #[test]
    fn csv_cells() {
        let got = pairs(r#"date=2024-01-05,devname="FG100","msg=""a, b""",policyid=3"#);
        assert_eq!(
            got,
            [
                pair("date", "2024-01-05"),
                pair("devname", "FG100"),
                pair("msg", "a, b"),
                pair("policyid", "3"),
            ]
        );
    }

    #[test]
    fn unclosed_quote() {
        assert_eq!(pairs("msg=\"cut"), [pair("msg", "cut")]);
    }
}
