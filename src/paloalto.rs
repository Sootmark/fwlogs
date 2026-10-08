//! Palo Alto Networks PAN-OS: syslog lines and the web interface's CSV
//! export.
//!
//! A syslog line is CSV, its fields positional, in the order PAN-OS 11.1's
//! documentation gives for each log type (the lists below, `FUTURE_USE`
//! fields skipped). Older versions write fewer fields, newer ones more: a
//! missing trailing field is absent, an extra one kept as `Field <index>`.
//! An export's columns are named in its header row (`Receive Time,Serial
//! #,Type,Threat/Content Type,…`), and found by name, normalised.

use common::time::Ts;

use crate::{csv, normalise, syslog, time, Entry, Mapping, Parsed, Vendor};

const MAPPING: Mapping = Mapping {
    action: &["action", "result", "status", "eventtype"],
    source: &["sourceaddress", "sourceip", "publicip", "host"],
    source_port: &["sourceport"],
    destination: &["destinationaddress"],
    destination_port: &["destinationport"],
    protocol: &["protocol", "ipprotocol"],
    user: &["sourceuser", "user", "admin"],
    application: &["application"],
    rule: &["rulename", "rule", "authenticationpolicy"],
    device: &["devicename", "serialnumber", "serial", "sysloghost"],
    message: &[
        "description",
        "configurationpath",
        "urlfilename",
        "threatid",
        "threatcontentname",
    ],
};

/// The log type, by its name in the lists and in exports.
const TYPE: &[&str] = &["type"];
/// The subtype, likewise.
const SUBTYPE: &[&str] = &["threatcontenttype", "contentthreattype", "subtype"];

/// The zoned time.
const HIGH_RESOLUTION: &[&str] = &["highresolutiontimestamp", "highrestimestamp"];
/// The firewall's local time.
const GENERATED: &[&str] = &["generatedtime", "generatetime"];

/// A syslog line, from its first field (`1,2024/02/22 12:32:26,…`), after
/// any header.
pub(crate) fn read(line: &str) -> Option<Result<Parsed, String>> {
    let start = record_start(line)?;
    let (prefix, record) = line.split_at(start);
    let cells = csv::cells(record);
    let log_type = cells.get(3).filter(|t| is_type(t))?;
    let names = layout(log_type);
    let header = syslog::split(prefix);
    let mut entry = Entry::new(Vendor::PaloAlto, &header);
    for (index, value) in cells.iter().enumerate() {
        match names.get(index) {
            Some(&"FUTURE_USE") => {}
            Some(name) => entry.put(name, value),
            None => entry.put(&format!("Field {index}"), value),
        }
    }
    Some(Ok(finish(entry, header.time)))
}

/// Whether `line` is an export's header row.
pub(crate) fn is_export_header(line: &str) -> bool {
    let names: Vec<String> = csv::cells(line).iter().map(|c| normalise(c)).collect();
    names.iter().any(|n| n == "receivetime") && names.iter().any(|n| n == "type")
}

/// An export's rows, each with its first line.
pub(crate) fn export(text: &str) -> Vec<(usize, Result<Parsed, String>)> {
    let rows = csv::rows(text);
    let Some(((_, header), rows)) = rows.split_first() else {
        return Vec::new();
    };
    rows.iter()
        .map(|(line, row)| {
            let mut entry = Entry::new(Vendor::PaloAlto, &syslog::Header::default());
            for (index, value) in row.iter().enumerate() {
                match header.get(index).filter(|name| !name.trim().is_empty()) {
                    Some(name) => entry.put(name.trim(), value),
                    None => entry.put(&format!("Field {index}"), value),
                }
            }
            (*line, Ok(finish(entry, None)))
        })
        .collect()
}

/// Where a record starts: the field before its receive time
/// (`,YYYY/MM/DD HH:MM:SS,`), digits after a space or the line's start.
fn record_start(line: &str) -> Option<usize> {
    line.match_indices(',').find_map(|(comma, _)| {
        let stamp = line.get(comma + 1..comma + 20)?;
        if line.get(comma + 20..comma + 21) != Some(",") || time::slashed(stamp).is_none() {
            return None;
        }
        let before = line.get(..comma)?;
        let start = before.rfind(' ').map_or(0, |space| space + 1);
        let future_use = before.get(start..)?;
        future_use
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then_some(start)
    })
}

/// `TRAFFIC`, `THREAT`, `HIPMATCH`: upper case letters.
fn is_type(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_uppercase())
}

/// The fields of a log type, in order; the first seven, common to all, for
/// types not listed.
fn layout(log_type: &str) -> &'static [&'static str] {
    match log_type {
        "TRAFFIC" => &TRAFFIC,
        "THREAT" => &THREAT,
        "CONFIG" => &CONFIG,
        "SYSTEM" => &SYSTEM,
        "GLOBALPROTECT" => &GLOBALPROTECT,
        "AUTHENTICATION" => &AUTHENTICATION,
        _ => &COMMON,
    }
}

/// The kind, time and main values of an entry whose fields are named.
fn finish(mut entry: Entry, header_time: Option<Ts>) -> Parsed {
    entry.kind = match (entry.first(TYPE), entry.first(SUBTYPE)) {
        (Some(log_type), Some(subtype)) => Some(format!("{log_type}/{subtype}")),
        (log_type, _) => log_type.map(str::to_owned),
    };
    let (time, damage) = entry_time(&entry);
    entry.time = time.or(header_time);
    entry.fill(&MAPPING);
    Parsed { entry, damage }
}

/// A time's reader.
type TimeReader = fn(&str) -> Option<Ts>;

/// The high resolution timestamp, else the generated time; and which of
/// them couldn't be read.
fn entry_time(entry: &Entry) -> (Option<Ts>, Option<String>) {
    let candidates: [(&[&str], TimeReader); 2] =
        [(HIGH_RESOLUTION, time::iso8601), (GENERATED, time::slashed)];
    let mut damage = None;
    for (names, parse) in candidates {
        let Some(text) = entry.first(names) else {
            continue;
        };
        match parse(text) {
            Some(time) => return (Some(time), damage),
            None => damage = Some(format!("time {text:?} not read")),
        }
    }
    (None, damage)
}

/// The fields every log type starts with.
const COMMON: [&str; 7] = [
    "FUTURE_USE",
    "Receive Time",
    "Serial Number",
    "Type",
    "Threat/Content Type",
    "FUTURE_USE",
    "Generated Time",
];

/// TRAFFIC logs' fields, in order (PAN-OS 11.1).
const TRAFFIC: [&str; 130] = [
    "FUTURE_USE",
    "Receive Time",
    "Serial Number",
    "Type",
    "Threat/Content Type",
    "FUTURE_USE",
    "Generated Time",
    "Source Address",
    "Destination Address",
    "NAT Source IP",
    "NAT Destination IP",
    "Rule Name",
    "Source User",
    "Destination User",
    "Application",
    "Virtual System",
    "Source Zone",
    "Destination Zone",
    "Inbound Interface",
    "Outbound Interface",
    "Log Action",
    "FUTURE_USE",
    "Session ID",
    "Repeat Count",
    "Source Port",
    "Destination Port",
    "NAT Source Port",
    "NAT Destination Port",
    "Flags",
    "Protocol",
    "Action",
    "Bytes",
    "Bytes Sent",
    "Bytes Received",
    "Packets",
    "Start Time",
    "Elapsed Time",
    "Category",
    "FUTURE_USE",
    "Sequence Number",
    "Action Flags",
    "Source Country",
    "Destination Country",
    "FUTURE_USE",
    "Packets Sent",
    "Packets Received",
    "Session End Reason",
    "Device Group Hierarchy Level 1",
    "Device Group Hierarchy Level 2",
    "Device Group Hierarchy Level 3",
    "Device Group Hierarchy Level 4",
    "Virtual System Name",
    "Device Name",
    "Action Source",
    "Source VM UUID",
    "Destination VM UUID",
    "Tunnel ID/IMSI",
    "Monitor Tag/IMEI",
    "Parent Session ID",
    "Parent Start Time",
    "Tunnel Type",
    "SCTP Association ID",
    "SCTP Chunks",
    "SCTP Chunks Sent",
    "SCTP Chunks Received",
    "Rule UUID",
    "HTTP/2 Connection",
    "App Flap Count",
    "Policy ID",
    "Link Switches",
    "SD-WAN Cluster",
    "SD-WAN Device Type",
    "SD-WAN Cluster Type",
    "SD-WAN Site",
    "Dynamic User Group Name",
    "XFF Address",
    "Source Device Category",
    "Source Device Profile",
    "Source Device Model",
    "Source Device Vendor",
    "Source Device OS Family",
    "Source Device OS Version",
    "Source Hostname",
    "Source Mac Address",
    "Destination Device Category",
    "Destination Device Profile",
    "Destination Device Model",
    "Destination Device Vendor",
    "Destination Device OS Family",
    "Destination Device OS Version",
    "Destination Hostname",
    "Destination Mac Address",
    "Container ID",
    "POD Namespace",
    "POD Name",
    "Source External Dynamic List",
    "Destination External Dynamic List",
    "Host ID",
    "Serial Number",
    "Source Dynamic Address Group",
    "Destination Dynamic Address Group",
    "Session Owner",
    "High Resolution Timestamp",
    "A Slice Service Type",
    "A Slice Differentiator",
    "Application Subcategory",
    "Application Category",
    "Application Technology",
    "Application Risk",
    "Application Characteristic",
    "Application Container",
    "Tunneled Application",
    "Application SaaS",
    "Application Sanctioned State",
    "Offloaded",
    "Flow Type",
    "Cluster Name",
    "AI Traffic",
    "AI Forward Error",
    "K8S Cluster ID",
    "tcp_rtt_c2s",
    "tcp_rtt_s2c",
    "total_n_ooseq_c2s",
    "total_n_ooseq_s2c",
    "tcp_retransit_cnt_c2s",
    "tcp_retransit_cnt_s2c",
    "tcp_zero_window_cnt_c2s",
    "tcp_zero_window_cnt_s2c",
    "Source Adv DevID",
    "Destination Adv DevID",
];

/// THREAT logs' fields, in order (PAN-OS 11.1).
const THREAT: [&str; 123] = [
    "FUTURE_USE",
    "Receive Time",
    "Serial Number",
    "Type",
    "Threat/Content Type",
    "FUTURE_USE",
    "Generated Time",
    "Source Address",
    "Destination Address",
    "NAT Source IP",
    "NAT Destination IP",
    "Rule Name",
    "Source User",
    "Destination User",
    "Application",
    "Virtual System",
    "Source Zone",
    "Destination Zone",
    "Inbound Interface",
    "Outbound Interface",
    "Log Action",
    "FUTURE_USE",
    "Session ID",
    "Repeat Count",
    "Source Port",
    "Destination Port",
    "NAT Source Port",
    "NAT Destination Port",
    "Flags",
    "IP Protocol",
    "Action",
    "URL/Filename",
    "Threat ID",
    "Category",
    "Severity",
    "Direction",
    "Sequence Number",
    "Action Flags",
    "Source Location",
    "Destination Location",
    "FUTURE_USE",
    "Content Type",
    "PCAP_ID",
    "File Digest",
    "Cloud",
    "URL Index",
    "User Agent",
    "File Type",
    "X-Forwarded-For",
    "Referer",
    "Sender",
    "Subject",
    "Recipient",
    "Report ID",
    "Device Group Hierarchy Level 1",
    "Device Group Hierarchy Level 2",
    "Device Group Hierarchy Level 3",
    "Device Group Hierarchy Level 4",
    "Virtual System Name",
    "Device Name",
    "FUTURE_USE",
    "Source VM UUID",
    "Destination VM UUID",
    "HTTP Method",
    "Tunnel ID/IMSI",
    "Monitor Tag/IMEI",
    "Parent Session ID",
    "Parent Start Time",
    "Tunnel Type",
    "Threat Category",
    "Content Version",
    "FUTURE_USE",
    "SCTP Association ID",
    "Payload Protocol ID",
    "HTTP Headers",
    "URL Category List",
    "Rule UUID",
    "HTTP/2 Connection",
    "Dynamic User Group Name",
    "XFF Address",
    "Source Device Category",
    "Source Device Profile",
    "Source Device Model",
    "Source Device Vendor",
    "Source Device OS Family",
    "Source Device OS Version",
    "Source Hostname",
    "Source MAC Address",
    "Destination Device Category",
    "Destination Device Profile",
    "Destination Device Model",
    "Destination Device Vendor",
    "Destination Device OS Family",
    "Destination Device OS Version",
    "Destination Hostname",
    "Destination MAC Address",
    "Container ID",
    "POD Namespace",
    "POD Name",
    "Source External Dynamic List",
    "Destination External Dynamic List",
    "Host ID",
    "Serial Number",
    "Domain EDL",
    "Source Dynamic Address Group",
    "Destination Dynamic Address Group",
    "Partial Hash",
    "High Resolution Timestamp",
    "Reason",
    "Justification",
    "A Slice Service Type",
    "Application Subcategory",
    "Application Category",
    "Application Technology",
    "Application Risk",
    "Application Characteristic",
    "Application Container",
    "Tunneled Application",
    "Application SaaS",
    "Application Sanctioned State",
    "Cloud Report ID",
    "Flow Type",
    "Cluster Name",
];

/// CONFIG logs' fields, in order (PAN-OS 11.1).
const CONFIG: [&str; 28] = [
    "FUTURE_USE",
    "Receive Time",
    "Serial Number",
    "Type",
    "Subtype",
    "FUTURE_USE",
    "Generated Time",
    "Host",
    "Virtual System",
    "Command",
    "Admin",
    "Client",
    "Result",
    "Configuration Path",
    "Before Change Detail",
    "After Change Detail",
    "Sequence Number",
    "Action Flags",
    "Device Group Hierarchy Level 1",
    "Device Group Hierarchy Level 2",
    "Device Group Hierarchy Level 3",
    "Device Group Hierarchy Level 4",
    "Virtual System Name",
    "Device Name",
    "Device Group",
    "Audit Comment",
    "FUTURE_USE",
    "High Resolution Timestamp",
];

/// SYSTEM logs' fields, in order (PAN-OS 11.1).
const SYSTEM: [&str; 26] = [
    "FUTURE_USE",
    "Receive Time",
    "Serial Number",
    "Type",
    "Content/Threat Type",
    "FUTURE_USE",
    "Generated Time",
    "Virtual System",
    "Event ID",
    "Object",
    "FUTURE_USE",
    "FUTURE_USE",
    "Module",
    "Severity",
    "Description",
    "Sequence Number",
    "Action Flags",
    "Device Group Hierarchy Level 1",
    "Device Group Hierarchy Level 2",
    "Device Group Hierarchy Level 3",
    "Device Group Hierarchy Level 4",
    "Virtual System Name",
    "Device Name",
    "FUTURE_USE",
    "FUTURE_USE",
    "High Resolution Timestamp",
];

/// GLOBALPROTECT logs' fields, in order (PAN-OS 11.1).
const GLOBALPROTECT: [&str; 50] = [
    "FUTURE_USE",
    "Receive Time",
    "Serial Number",
    "Type",
    "Threat/Content Type",
    "FUTURE_USE",
    "Generated Time",
    "Virtual System",
    "Event ID",
    "Stage",
    "Authentication Method",
    "Tunnel Type",
    "Source User",
    "Source Region",
    "Machine Name",
    "Public IP",
    "Public IPv6",
    "Private IP",
    "Private IPv6",
    "Host ID",
    "Serial Number",
    "Client Version",
    "Client OS",
    "Client OS Version",
    "Repeat Count",
    "Reason",
    "Error",
    "Description",
    "Status",
    "Location",
    "Login Duration",
    "Connect Method",
    "Error Code",
    "Portal",
    "Sequence Number",
    "Action Flags",
    "High Res Timestamp",
    "Selection Type",
    "Response Time",
    "Priority",
    "Attempted Gateways",
    "Gateway",
    "Device Group Hierarchy Level 1",
    "Device Group Hierarchy Level 2",
    "Device Group Hierarchy Level 3",
    "Device Group Hierarchy Level 4",
    "Virtual System Name",
    "Device Name",
    "Virtual System ID",
    "Cluster Name",
];

/// AUTHENTICATION logs' fields, in order (PAN-OS 11.1).
const AUTHENTICATION: [&str; 47] = [
    "FUTURE_USE",
    "Receive Time",
    "Serial Number",
    "Type",
    "Threat/Content Type",
    "FUTURE_USE",
    "Generated Time",
    "Virtual System",
    "Source IP",
    "User",
    "Normalize User",
    "Object",
    "Authentication Policy",
    "Repeat Count",
    "Authentication ID",
    "Vendor",
    "Log Action",
    "Server Profile",
    "Description",
    "Client Type",
    "Event Type",
    "Factor Number",
    "Sequence Number",
    "Action Flags",
    "Device Group Hierarchy 1",
    "Device Group Hierarchy 2",
    "Device Group Hierarchy 3",
    "Device Group Hierarchy 4",
    "Virtual System Name",
    "Device Name",
    "Virtual System ID",
    "Authentication Protocol",
    "UUID for rule",
    "High Resolution Timestamp",
    "Source Device Category",
    "Source Device Profile",
    "Source Device Model",
    "Source Device Vendor",
    "Source Device OS Family",
    "Source Device OS Version",
    "Source Hostname",
    "Source Mac Address",
    "Region",
    "FUTURE_USE",
    "User Agent",
    "Session ID",
    "Cluster Name",
];
