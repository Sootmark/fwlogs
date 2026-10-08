//! Cisco ASA syslog: `%ASA-<severity>-<id>: <text>`, after an optional
//! timestamp (`:2025-10-30T11:04:10Z:` with `logging timestamp rfc5424`,
//! `Oct 30 2025 11:04:10` otherwise) and device id.
//!
//! The text is read by message id, as Cisco's "Secure Firewall ASA Series
//! Syslog Messages" words it:
//!
//! - 302013, 302015: a TCP or UDP connection built, `for` one end `to` the
//!   other; for an inbound connection the first end is the source, for an
//!   outbound one the second.
//! - 302014, 302016: a connection torn down: its ends, which a teardown
//!   doesn't orient, as `first_…` and `second_…`; its duration, bytes and
//!   reason.
//! - 106023 (denied by an access group), 106100 (permitted or denied by an
//!   access list), 106015 (TCP without a connection denied), 710005
//!   (request to the box discarded), 609002 (local host torn down).
//! - 113004, 113005, 113015: AAA authentication successful or rejected.
//! - 113039, 716001, 716002, 722022, 722023, 722037: AnyConnect and WebVPN
//!   sessions: group, user, address.
//! - 605004, 605005: a login to the box denied or permitted; 611103: a
//!   logout.
//! - 111008, 111009, 111010: a command executed: user, command, address.
//! - 502101, 502102, 502103: a local user added, deleted, or its privilege
//!   changed.
//!
//! Other ids are entries all the same, with their severity, id and text.

use common::time::Ts;

use crate::{syslog, time, Entry, Mapping, Parsed, Vendor};

const MAPPING: Mapping = Mapping {
    action: &["action"],
    source: &["sourceaddress"],
    source_port: &["sourceport"],
    destination: &["destinationaddress"],
    destination_port: &["destinationport"],
    protocol: &["protocol"],
    user: &["user", "uname"],
    application: &["application", "destinationservice"],
    rule: &["rule"],
    device: &["deviceid", "sysloghost"],
    message: &[],
};

/// A message's reader: its parts, or `None` when it isn't worded as
/// documented.
type MessageReader = fn(&str) -> Option<Parts>;

/// A line holding `%ASA-`.
pub(crate) fn read(line: &str) -> Option<Result<Parsed, String>> {
    let at = line.find("%ASA-")?;
    let (prefix, message) = line.split_at(at);
    Some(entry(prefix, message))
}

/// The entry of a message, `prefix` holding any syslog header, timestamp
/// and device id.
fn entry(prefix: &str, message: &str) -> Result<Parsed, String> {
    let (severity, id, text) = split_message(message).ok_or("an %ASA- message not read")?;
    let header = syslog::split(prefix);
    let stamp = Stamp::read(header.body);
    let mut entry = Entry::new(Vendor::CiscoAsa, &header);
    if let Some(device) = stamp.device {
        entry.put("device_id", device);
    }
    entry.put("severity", severity);
    let mut damage = None;
    if let Some(reader) = reader(id) {
        match reader(text) {
            Some(parts) => entry.fields.extend(parts.0),
            None => damage = Some(format!("{id}: not worded as documented")),
        }
    }
    entry.kind = Some(id.to_owned());
    entry.time = stamp.time.or(header.time);
    entry.fill(&MAPPING);
    entry.message = Some(text.to_owned()).filter(|t| !t.is_empty());
    Ok(Parsed { entry, damage })
}

/// `%ASA-6-302013: text` as its severity, id and text.
fn split_message(message: &str) -> Option<(&str, &str, &str)> {
    let rest = message.strip_prefix("%ASA-")?;
    let (severity, rest) = rest.split_once('-')?;
    let (id, text) = rest.split_once(':')?;
    let is_severity = severity.len() == 1 && severity.bytes().all(|b| (b'0'..=b'7').contains(&b));
    let is_id = (1..=6).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit());
    (is_severity && is_id).then(|| (severity, id, text.trim()))
}

/// The reader of the messages this crate reads.
fn reader(id: &str) -> Option<MessageReader> {
    Some(match id {
        "302013" | "302015" => built,
        "302014" | "302016" => teardown,
        "106023" => access_group,
        "106100" => access_list,
        "106015" => no_connection,
        "710005" => discarded,
        "609002" => local_host,
        "113004" | "113005" | "113015" => aaa,
        "113039" | "716001" | "716002" | "722022" | "722023" | "722037" => session,
        "605004" | "605005" => login,
        "611103" => logout,
        "111008" => executed_the,
        "111009" => executed_cmd,
        "111010" => executed_from,
        "502101" | "502102" | "502103" => local_user,
        _ => return None,
    })
}

/// The time and device id before the message.
#[derive(Default)]
struct Stamp<'a> {
    time: Option<Ts>,
    device: Option<&'a str>,
}

impl<'a> Stamp<'a> {
    /// `:2025-10-30T11:04:10Z:`, `Oct 30 2025 11:04:10:`, then perhaps a
    /// device id; colons around words dropped.
    fn read(text: &'a str) -> Self {
        let words: Vec<&str> = text
            .split_whitespace()
            .map(|word| word.trim_matches(':'))
            .filter(|word| !word.is_empty())
            .collect();
        let mut stamp = Self::default();
        let mut at = 0;
        while let Some(word) = words.get(at) {
            if let Some(time) = time::iso8601(word) {
                stamp.time = Some(time);
                at += 1;
            } else if let Some(time) = legacy(words.get(at..at + 4)) {
                stamp.time = Some(time);
                at += 4;
            } else {
                stamp.device = Some(word);
                at += 1;
            }
        }
        stamp
    }
}

/// `Oct 30 2025 11:04:10`.
fn legacy(words: Option<&[&str]>) -> Option<Ts> {
    match words? {
        [month, day, year, clock] => time::named_month(month, day, year, clock),
        _ => None,
    }
}

/// Named values found in a message.
#[derive(Debug, Default)]
struct Parts(Vec<(String, String)>);

impl Parts {
    /// Adds a value, if not empty.
    fn put(&mut self, name: &str, value: &str) -> &mut Self {
        let value = value.trim();
        if !value.is_empty() {
            self.0.push((name.to_owned(), value.to_owned()));
        }
        self
    }

    /// `interface:address/port` as `<role>_interface`, `<role>_address` and
    /// `<role>_port` (`<role>_service` for a name, `ssh`).
    fn endpoint(&mut self, role: &str, text: &str) -> &mut Self {
        match text.split_once(':') {
            Some((interface, address)) => {
                self.put(&format!("{role}_interface"), interface);
                self.address(role, address)
            }
            None => self.address(role, text),
        }
    }

    /// `address/port` (or `address/service`, or an address alone).
    fn address(&mut self, role: &str, text: &str) -> &mut Self {
        let (address, port) = text.rsplit_once('/').unwrap_or((text, ""));
        self.put(&format!("{role}_address"), address);
        let suffix = if port.bytes().all(|b| b.is_ascii_digit()) {
            "port"
        } else {
            "service"
        };
        self.put(&format!("{role}_{suffix}"), port)
    }

    /// `interface/address(port)`, as access lists write ends.
    fn acl_endpoint(&mut self, role: &str, text: &str) -> &mut Self {
        let (interface, rest) = text.split_once('/').unwrap_or(("", text));
        let (address, port) = rest.split_once('(').unwrap_or((rest, ""));
        self.put(&format!("{role}_interface"), interface)
            .put(&format!("{role}_address"), address)
            .put(&format!("{role}_port"), port.trim_end_matches(')'))
    }

    /// `Label: value Other: value` as `label` and `other`.
    fn labels(&mut self, text: &str) -> &mut Self {
        let mut name: Option<String> = None;
        let mut value: Vec<&str> = Vec::new();
        for word in text.split_whitespace() {
            match word.strip_suffix(':').filter(|label| !label.is_empty()) {
                Some(label) => {
                    if let Some(name) = name.replace(label.to_ascii_lowercase()) {
                        self.put(&name, &value.join(" "));
                    }
                    value.clear();
                }
                None => value.push(word),
            }
        }
        if let Some(name) = name {
            self.put(&name, &value.join(" "));
        }
        self
    }

    /// Whether a value is named `name`.
    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|(n, _)| n == name)
    }
}

/// `text`'s words.
fn words(text: &str) -> Vec<&str> {
    text.split_whitespace().collect()
}

/// The word after the first `marker`.
fn after<'a>(words: &[&'a str], marker: &str) -> Option<&'a str> {
    let at = words.iter().position(|word| *word == marker)?;
    words.get(at + 1).copied()
}

/// The first of `verbs` found in `text`.
fn verb<'a>(text: &str, verbs: &[&'a str]) -> Option<&'a str> {
    verbs.iter().copied().find(|verb| text.contains(verb))
}

/// `Built inbound TCP connection 2019 for management:198.51.100.7/55608
/// (198.51.100.7/55608) to identity:192.0.2.1/443 (192.0.2.1/443)`.
fn built(text: &str) -> Option<Parts> {
    let w = words(text);
    if w.first() != Some(&"Built") {
        return None;
    }
    let direction = *w.get(1)?;
    let (first, second) = (after(&w, "for")?, after(&w, "to")?);
    let (source, destination) = match direction {
        "inbound" => (first, second),
        "outbound" => (second, first),
        _ => return None,
    };
    let mut parts = Parts::default();
    parts
        .put("action", "built")
        .put("direction", direction)
        .put("protocol", w.get(2)?)
        .put("connection_id", after(&w, "connection")?)
        .endpoint("source", source)
        .endpoint("destination", destination);
    Some(parts)
}

/// `Teardown TCP connection 2019 for management:198.51.100.7/55608 to
/// identity:192.0.2.1/443 duration 0:00:00 bytes 1285 TCP Reset-O from
/// identity`.
fn teardown(text: &str) -> Option<Parts> {
    let w = words(text);
    if w.first() != Some(&"Teardown") {
        return None;
    }
    let bytes_at = w.iter().position(|word| *word == "bytes")?;
    let tail = w.get(bytes_at + 2..).unwrap_or_default();
    let reason: Vec<&str> = tail
        .iter()
        .copied()
        .take_while(|word| *word != "from" && !word.starts_with('('))
        .collect();
    let mut parts = Parts::default();
    parts
        .put("action", "teardown")
        .put("protocol", w.get(1)?)
        .put("connection_id", after(&w, "connection")?)
        .endpoint("first", after(&w, "for")?)
        .endpoint("second", after(&w, "to")?)
        .put("duration", after(&w, "duration").unwrap_or_default())
        .put("bytes", w.get(bytes_at + 1)?)
        .put("reason", &reason.join(" "))
        .put(
            "teardown_initiator",
            after(tail, "from").unwrap_or_default(),
        );
    Some(parts)
}

/// `Deny tcp src outside:192.0.2.10/51515 dst inside:198.51.100.5/445 by
/// access-group "outside_access_in" [0x0, 0x0]`.
fn access_group(text: &str) -> Option<Parts> {
    let w = words(text);
    if w.first() != Some(&"Deny") {
        return None;
    }
    let mut parts = Parts::default();
    parts
        .put("action", "deny")
        .put("protocol", w.get(1)?)
        .endpoint("source", after(&w, "src")?)
        .endpoint("destination", after(&w, "dst")?)
        .put("rule", after(&w, "access-group")?.trim_matches('"'));
    Some(parts)
}

/// `access-list outside_access_in denied tcp outside/192.0.2.10(51515) ->
/// inside/198.51.100.5(445) hit-cnt 1 first hit [0x91c26a3, 0x0]`.
fn access_list(text: &str) -> Option<Parts> {
    let w = words(text);
    if w.first() != Some(&"access-list") {
        return None;
    }
    let destination = after(&w, "->").or_else(|| w.get(5).copied())?;
    let mut parts = Parts::default();
    parts
        .put("rule", w.get(1)?)
        .put("action", w.get(2)?)
        .put("protocol", w.get(3)?)
        .acl_endpoint("source", w.get(4)?)
        .acl_endpoint("destination", destination)
        .put("hit_count", after(&w, "hit-cnt").unwrap_or_default());
    Some(parts)
}

/// `Deny TCP (no connection) from 192.0.2.10/443 to 198.51.100.5/51515
/// flags RST on interface outside`.
fn no_connection(text: &str) -> Option<Parts> {
    let w = words(text);
    if w.first() != Some(&"Deny") {
        return None;
    }
    let flags: Vec<&str> = w
        .iter()
        .copied()
        .skip_while(|word| *word != "flags")
        .skip(1)
        .take_while(|word| *word != "on")
        .collect();
    let mut parts = Parts::default();
    parts
        .put("action", "deny")
        .put("protocol", w.get(1)?)
        .address("source", after(&w, "from")?)
        .address("destination", after(&w, "to")?)
        .put("flags", &flags.join(" "))
        .put("interface", after(&w, "interface").unwrap_or_default());
    Some(parts)
}

/// `TCP request discarded from 198.51.100.7/55608 to
/// management:192.0.2.1/443`.
fn discarded(text: &str) -> Option<Parts> {
    let w = words(text);
    if w.get(2) != Some(&"discarded") {
        return None;
    }
    let mut parts = Parts::default();
    parts
        .put("action", "discarded")
        .put("protocol", w.first()?)
        .address("source", after(&w, "from")?)
        .endpoint("destination", after(&w, "to")?);
    Some(parts)
}

/// `Teardown local-host management:198.51.100.7 duration 0:02:01`.
fn local_host(text: &str) -> Option<Parts> {
    let w = words(text);
    let mut parts = Parts::default();
    parts
        .put("action", "teardown")
        .endpoint("host", after(&w, "local-host")?)
        .put("duration", after(&w, "duration").unwrap_or_default());
    Some(parts)
}

/// `AAA user authentication Rejected : reason = Invalid password : local
/// database : user = alice : user IP = 203.0.113.5`.
fn aaa(text: &str) -> Option<Parts> {
    let mut segments = text.split(" : ");
    let head = words(segments.next()?);
    if head.first() != Some(&"AAA") {
        return None;
    }
    let mut parts = Parts::default();
    parts
        .put("action", &head.last()?.to_ascii_lowercase())
        .put("aaa_type", head.get(2)?);
    for (key, value) in segments.filter_map(|segment| segment.split_once('=')) {
        let name = match key.trim() {
            "user IP" => "source_address".to_owned(),
            key => key.to_ascii_lowercase().replace(' ', "_"),
        };
        parts.put(&name, value);
    }
    Some(parts)
}

/// `Group <GP-Staff> User <alice> IP <203.0.113.8> AnyConnect parent
/// session started.`, and the like: SVC connections established,
/// terminated or closing, WebVPN sessions started and terminated.
fn session(text: &str) -> Option<Parts> {
    let (group, rest) = labelled(text, "Group")?;
    let (user, rest) = labelled(rest, "User")?;
    let (address, rest) = labelled(rest, "IP")?;
    let protocol = rest
        .split_whitespace()
        .next()
        .filter(|word| matches!(*word, "TCP" | "UDP"));
    let reason = rest
        .split_once(':')
        .map(|(_, reason)| reason.trim().trim_end_matches('.'));
    let mut parts = Parts::default();
    parts
        .put(
            "action",
            verb(rest, &["started", "established", "terminated", "closing"])?,
        )
        .put("group", group)
        .put("user", user)
        .put("source_address", address)
        .put("protocol", protocol.unwrap_or_default())
        .put("reason", reason.unwrap_or_default());
    Some(parts)
}

/// `Label <value>` (or `Label value`) at the start of `text`, and the rest.
fn labelled<'a>(text: &'a str, label: &str) -> Option<(&'a str, &'a str)> {
    let rest = text.trim_start().strip_prefix(label)?.strip_prefix(' ')?;
    match rest.strip_prefix('<') {
        Some(inside) => inside.split_once('>'),
        None => Some(rest.split_once(' ').unwrap_or((rest, ""))),
    }
}

/// `Login denied from 203.0.113.9/40000 to outside:192.0.2.1/ssh for user
/// "admin"`.
fn login(text: &str) -> Option<Parts> {
    let w = words(text);
    if w.first() != Some(&"Login") {
        return None;
    }
    let (_, user) = text.split_once("for user ")?;
    let mut parts = Parts::default();
    parts
        .put("action", w.get(1)?)
        .address("source", after(&w, "from")?)
        .endpoint("destination", after(&w, "to")?)
        .put("user", user.trim().trim_matches('"'));
    Some(parts)
}

/// `User logged out: Uname: admin`.
fn logout(text: &str) -> Option<Parts> {
    let (_, labels) = text.split_once(':')?;
    let mut parts = Parts::default();
    parts.put("action", "logged out").labels(labels);
    parts.has("uname").then_some(parts)
}

/// `User 'admin' executed the 'logging emblem' command.`
fn executed_the(text: &str) -> Option<Parts> {
    let (user, rest) = quoted_word(text.strip_prefix("User ")?)?;
    let command = rest
        .trim()
        .strip_prefix("executed the ")?
        .trim_end_matches('.')
        .strip_suffix(" command")?;
    Some(command_parts(user, command.trim().trim_matches('\'')))
}

/// `User 'admin' executed cmd: show memory`.
fn executed_cmd(text: &str) -> Option<Parts> {
    let (user, rest) = quoted_word(text.strip_prefix("User ")?)?;
    let command = rest.trim().strip_prefix("executed cmd:")?;
    Some(command_parts(user, command.trim()))
}

/// `User 'admin', running 'CLI' from IP 198.51.100.7, executed 'write
/// memory'`.
fn executed_from(text: &str) -> Option<Parts> {
    let (user, rest) = quoted_word(text.strip_prefix("User ")?)?;
    let rest = rest
        .trim_start_matches(',')
        .trim()
        .strip_prefix("running ")?;
    let (application, rest) = quoted_word(rest)?;
    let rest = rest
        .trim_start_matches(',')
        .trim()
        .strip_prefix("from IP ")?;
    let (address, rest) = rest.split_once(',')?;
    let command = rest.trim().strip_prefix("executed ")?;
    let mut parts = command_parts(user, command.trim().trim_matches('\''));
    parts
        .put("application", application)
        .put("source_address", address);
    Some(parts)
}

fn command_parts(user: &str, command: &str) -> Parts {
    let mut parts = Parts::default();
    parts
        .put("action", "executed")
        .put("user", user)
        .put("command", command);
    parts
}

/// `'quoted words'` or a bare word (to a space or comma), and the rest.
fn quoted_word(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    if let Some(inside) = text.strip_prefix('\'') {
        return inside.split_once('\'');
    }
    let end = text.find([' ', ',']).unwrap_or(text.len());
    Some(text.split_at(end))
}

/// `New user added to local dbase: Uname: alice Priv: 2 Encpass: *****`,
/// `User deleted from local dbase: …`, `User priv level changed: Uname:
/// alice From: 2 To: 15`.
fn local_user(text: &str) -> Option<Parts> {
    let (head, labels) = text.split_once(':')?;
    let mut parts = Parts::default();
    parts
        .put("action", verb(head, &["added", "deleted", "changed"])?)
        .labels(labels);
    parts.has("uname").then_some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(reader: MessageReader, text: &str) -> Vec<(String, String)> {
        reader(text).map(|p| p.0).unwrap_or_default()
    }

    fn get<'a>(parts: &'a [(String, String)], name: &str) -> Option<&'a str> {
        parts
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn outbound_is_oriented_from_the_second_end() {
        let p = parts(
            built,
            "Built outbound UDP connection 7 for outside:198.51.100.53/53 (198.51.100.53/53) to inside:192.0.2.20/53211 (203.0.113.1/53211)",
        );
        assert_eq!(get(&p, "source_address"), Some("192.0.2.20"));
        assert_eq!(get(&p, "destination_port"), Some("53"));
    }

    #[test]
    fn teardown_keeps_ends_unoriented() {
        let p = parts(
            teardown,
            "Teardown TCP connection 2019 for management:198.51.100.7/55608 to identity:192.0.2.1/443 duration 0:00:00 bytes 1285 TCP Reset-O from identity",
        );
        assert_eq!(get(&p, "first_address"), Some("198.51.100.7"));
        assert_eq!(get(&p, "second_port"), Some("443"));
        assert_eq!(get(&p, "reason"), Some("TCP Reset-O"));
        assert_eq!(get(&p, "teardown_initiator"), Some("identity"));
        assert_eq!(get(&p, "source_address"), None);
    }

    #[test]
    fn stamps() {
        let s = Stamp::read("Oct 30 2025 11:04:10 asa-edge-01 : ");
        assert!(s.time.is_some());
        assert_eq!(s.device, Some("asa-edge-01"));
        let s = Stamp::read(":2025-10-30T11:04:10Z: ");
        assert!(s.time.is_some());
        assert_eq!(s.device, None);
    }

    #[test]
    fn commands() {
        let p = parts(
            executed_from,
            "User 'admin', running 'N/A' from IP 198.51.100.7, executed 'logging emblem'",
        );
        assert_eq!(get(&p, "command"), Some("logging emblem"));
        assert_eq!(get(&p, "source_address"), Some("198.51.100.7"));
        let p = parts(
            executed_the,
            "User 'admin' executed the 'write memory' command.",
        );
        assert_eq!(get(&p, "command"), Some("write memory"));
        let p = parts(
            executed_cmd,
            "User 'enable_15' executed cmd: show checkheaps",
        );
        assert_eq!(get(&p, "user"), Some("enable_15"));
    }
}
