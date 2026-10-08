//! Firewall logs, for forensics: which connections were allowed or
//! denied, who logged in to the VPN or the firewall itself, and what its
//! administrators changed.
//!
//! - Palo Alto Networks PAN-OS: syslog lines, comma-separated, positional
//!   (the field order of each log type as PAN-OS 11.1 documents it; older
//!   versions stop earlier, so missing trailing fields are absent), and
//!   the web interface's CSV export, its columns found by name. TRAFFIC,
//!   THREAT, CONFIG, SYSTEM, GLOBALPROTECT and AUTHENTICATION logs are read
//!   by name; other types keep their common first fields. The time is the
//!   high resolution timestamp (ISO 8601 with offset), else the generated
//!   time (`2024/02/22 12:32:26`, the firewall's local time).
//! - Fortinet FortiGate: `key=value` lines (`date=2024-01-05
//!   time=10:22:33 … logid="0000000013" type="traffic" subtype="forward"
//!   …`), and the CSV the web interface's log download writes, one
//!   `key=value` per cell. The time is `eventtime` (seconds, milliseconds,
//!   microseconds or nanoseconds since 1970, by magnitude), else `date` and
//!   `time` with `tz` applied, else local.
//! - Cisco ASA: `%ASA-<severity>-<id>: <text>`, after an optional
//!   timestamp (`:2025-10-30T11:04:10Z:`, UTC, or `Oct 30 2025 11:04:10`,
//!   local). Connections built and torn down, access list denials, AAA and
//!   VPN logins, admin logins and commands, and local user changes are
//!   read by message id, as Cisco's syslog messages guide words them; other
//!   ids keep their severity, id and text.
//!
//! Any line may have a syslog header first (octet count, priority, RFC
//! 5424 or RFC 3164), and one file may mix the three vendors.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let log = fwlogs::read(&std::fs::read("firewall.log")?);
//! for entry in &log.entries {
//!     println!(
//!         "{:?} {:?} {:?} {:?} -> {:?}:{:?}",
//!         entry.time, entry.kind, entry.action, entry.source, entry.destination, entry.destination_port
//!     );
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Lines that can't be read go to `problems`, never a panic.

mod asa;
mod csv;
mod fortigate;
mod paloalto;
mod syslog;
mod time;

use common::time::Ts;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How many lines [`detect`] looks at.
const DETECT_LINES: usize = 32;

/// A firewall maker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Vendor {
    /// Palo Alto Networks PAN-OS.
    PaloAlto,
    /// Fortinet FortiGate.
    Fortinet,
    /// Cisco ASA.
    CiscoAsa,
}

impl Vendor {
    /// A short name (`panos`, `fortigate`, `asa`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PaloAlto => "panos",
            Self::Fortinet => "fortigate",
            Self::CiscoAsa => "asa",
        }
    }
}

/// One log line (or CSV row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Whose log it is.
    pub vendor: Vendor,
    /// Its line, from 1 (a CSV row's first line).
    pub line: usize,
    /// When: UTC from a zoned or epoch time, local (zone unknown) from a
    /// bare date and clock.
    pub time: Option<Ts>,
    /// What it is: PAN-OS's type and subtype (`TRAFFIC/end`), FortiGate's
    /// (`traffic/forward`), the ASA's message id (`302013`).
    pub kind: Option<String>,
    /// What was done or how it went (`allow`, `deny`, `accept`,
    /// `ssl-login-fail`, `built`, `teardown`, `rejected`, `executed`).
    pub action: Option<String>,
    /// The source address.
    pub source: Option<String>,
    /// The source port.
    pub source_port: Option<u16>,
    /// The destination address.
    pub destination: Option<String>,
    /// The destination port.
    pub destination_port: Option<u16>,
    /// The protocol, as written (`tcp`, `6`, `TCP`).
    pub protocol: Option<String>,
    /// The user or administrator.
    pub user: Option<String>,
    /// The application or service (`web-browsing`, `HTTPS`, `ssh`).
    pub application: Option<String>,
    /// The rule, policy or access list.
    pub rule: Option<String>,
    /// The firewall: its name, serial number or the syslog host.
    pub device: Option<String>,
    /// What it says: a description, a URL, a command, the ASA's text.
    pub message: Option<String>,
    /// Every labelled value, by name: PAN-OS's documented field names (or
    /// the export's column names), FortiGate's keys, the parts of an ASA
    /// message (`source_address`, `duration`, `command`, …); `syslog_time`
    /// and `syslog_host` from a syslog header. Empty values are left out.
    pub fields: Vec<(String, String)>,
}

impl Entry {
    /// An entry of `vendor` with the header's values as fields.
    fn new(vendor: Vendor, header: &syslog::Header) -> Self {
        let mut fields = Vec::new();
        for (name, value) in [("syslog_time", header.stamp), ("syslog_host", header.host)] {
            if let Some(value) = value {
                fields.push((name.to_owned(), value.to_owned()));
            }
        }
        Self {
            vendor,
            line: 0,
            time: None,
            kind: None,
            action: None,
            source: None,
            source_port: None,
            destination: None,
            destination_port: None,
            protocol: None,
            user: None,
            application: None,
            rule: None,
            device: None,
            message: None,
            fields,
        }
    }

    /// A value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Adds a value, if not empty.
    fn put(&mut self, name: &str, value: &str) {
        let value = value.trim();
        if !value.is_empty() {
            self.fields.push((name.to_owned(), value.to_owned()));
        }
    }

    /// The first value whose name, normalised, is one of `names` (first
    /// listed first).
    fn first(&self, names: &[&str]) -> Option<&str> {
        let normalised: Vec<String> = self.fields.iter().map(|(n, _)| normalise(n)).collect();
        lookup(&self.fields, &normalised, names)
    }

    /// The main values, found in `fields` as `mapping` says.
    fn fill(&mut self, mapping: &Mapping) {
        let fields = std::mem::take(&mut self.fields);
        let normalised: Vec<String> = fields.iter().map(|(n, _)| normalise(n)).collect();
        let text = |names: &[&str]| lookup(&fields, &normalised, names).map(str::to_owned);
        let port = |names: &[&str]| text(names).and_then(|p| p.parse().ok());
        self.action = text(mapping.action);
        self.source = text(mapping.source);
        self.source_port = port(mapping.source_port);
        self.destination = text(mapping.destination);
        self.destination_port = port(mapping.destination_port);
        self.protocol = text(mapping.protocol);
        self.user = text(mapping.user);
        self.application = text(mapping.application);
        self.rule = text(mapping.rule);
        self.device = text(mapping.device);
        self.message = text(mapping.message);
        self.fields = fields;
    }
}

/// In `fields`, whose names normalised are `normalised`, the value of the
/// first of `names` there.
fn lookup<'a>(
    fields: &'a [(String, String)],
    normalised: &[String],
    names: &[&str],
) -> Option<&'a str> {
    names.iter().find_map(|wanted| {
        let at = normalised.iter().position(|n| n == wanted)?;
        fields.get(at).map(|(_, value)| value.as_str())
    })
}

/// Where a vendor's main values are: field names, normalised (see
/// [`normalise`]), the first with a value winning.
struct Mapping {
    action: &'static [&'static str],
    source: &'static [&'static str],
    source_port: &'static [&'static str],
    destination: &'static [&'static str],
    destination_port: &'static [&'static str],
    protocol: &'static [&'static str],
    user: &'static [&'static str],
    application: &'static [&'static str],
    rule: &'static [&'static str],
    device: &'static [&'static str],
    message: &'static [&'static str],
}

/// A name in lower case, letters and digits only: `Source address`,
/// `Source Address` and `source_address` are one.
fn normalise(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// A line read: its entry, and what in it couldn't be.
struct Parsed {
    entry: Entry,
    damage: Option<String>,
}

/// A vendor's line reader: `None` when the line isn't its, an error when
/// it is but can't be read.
type Reader = fn(&str) -> Option<Result<Parsed, String>>;

/// The readers, tried in turn: the ASA's `%ASA-` and PAN-OS's dated CSV
/// are told apart more surely than FortiGate's `key=value`.
const READERS: [(Vendor, Reader); 3] = [
    (Vendor::CiscoAsa, asa::read),
    (Vendor::PaloAlto, paloalto::read),
    (Vendor::Fortinet, fortigate::read),
];

/// A file's entries and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirewallLog {
    /// The entries, in order.
    pub entries: Vec<Entry>,
    /// What couldn't be read, with why.
    pub problems: Vec<String>,
}

/// Whether `head` starts like a firewall log, and whose: the first of its
/// lines one of the vendors reads.
#[must_use]
pub fn detect(head: &[u8]) -> Option<Vendor> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text
        .trim_start_matches('\u{feff}')
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(DETECT_LINES)
        .peekable();
    if lines
        .peek()
        .is_some_and(|line| paloalto::is_export_header(line))
    {
        return Some(Vendor::PaloAlto);
    }
    lines.find_map(|line| {
        READERS
            .iter()
            .find(|(_, read)| read(line).is_some())
            .map(|(vendor, _)| *vendor)
    })
}

/// Read a file: syslog lines of any of the vendors, or a PAN-OS CSV
/// export.
#[must_use]
pub fn read(data: &[u8]) -> FirewallLog {
    let text = String::from_utf8_lossy(data);
    let text = text.trim_start_matches('\u{feff}');
    let mut log = FirewallLog::default();
    let first = text.lines().find(|line| !line.trim().is_empty());
    if first.is_some_and(paloalto::is_export_header) {
        for (line, parsed) in paloalto::export(text) {
            log.add(line, parsed);
        }
        return log;
    }
    let mut unread = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        match READERS.iter().find_map(|(_, read)| read(line)) {
            Some(parsed) => log.add(index + 1, parsed),
            None => unread.push(index + 1),
        }
    }
    match unread.as_slice() {
        [] => {}
        [line] => log
            .problems
            .push(format!("line {line}: no firewall log this crate reads")),
        [first, ..] => log.problems.push(format!(
            "{} lines of no firewall log this crate reads, the first line {first}",
            unread.len()
        )),
    }
    log
}

impl FirewallLog {
    /// Adds line `line`'s entry, or why it couldn't be read.
    fn add(&mut self, line: usize, parsed: Result<Parsed, String>) {
        match parsed {
            Ok(Parsed { mut entry, damage }) => {
                entry.line = line;
                self.entries.push(entry);
                if let Some(damage) = damage {
                    self.problems.push(format!("line {line}: {damage}"));
                }
            }
            Err(why) => self.problems.push(format!("line {line}: {why}")),
        }
    }
}
