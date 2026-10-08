# fwlogs

Firewall logs, for forensics: which connections were allowed or denied, who logged in to the VPN or to the firewall itself, and what its administrators changed, from Palo Alto, Fortinet and Cisco firewalls. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-fwlogs = "0.1"
```

```rust
let log = fwlogs::read(&std::fs::read("firewall.log")?);
for entry in &log.entries {
    println!("{:?} {:?} {:?} {:?} -> {:?}:{:?}", entry.time, entry.kind, entry.action, entry.source, entry.destination, entry.destination_port);
}
```

## What you get

- **Palo Alto PAN-OS**: syslog lines, each field by the name PAN-OS 11.1's documentation gives it in TRAFFIC, THREAT, CONFIG, SYSTEM, GLOBALPROTECT and AUTHENTICATION logs (older versions' shorter records read as far as they go; other types by their common fields); and the web interface's CSV export, its columns by name. The time is the high resolution timestamp (UTC), else the generated time (the firewall's local time).
- **Fortinet FortiGate**: `key=value` lines and the CSV log download (one `key=value` per cell): traffic (forward, local), events (system, user, SSL-VPN logins and tunnels), UTM (antivirus, web filter, IPS, application control). The time is `eventtime` (seconds to nanoseconds since 1970, told apart by magnitude), else `date` and `time` with `tz`, else local.
- **Cisco ASA**: `%ASA-<severity>-<id>:` messages, their timestamp (`:2025-10-30T11:04:10Z:` or `Oct 30 2025 11:04:10`) and device id, read by id as Cisco's syslog messages guide words them: connections built (the inbound or outbound end as the source) and torn down (both ends as `first_…` and `second_…`, the duration, bytes and reason), access group and access list denials, requests discarded, AAA authentications, AnyConnect and WebVPN sessions, logins to the box, commands executed, local users added, deleted or changed. Other ids keep their severity, id and text.
- Any line may carry a syslog header (an octet count, a priority, RFC 5424 or RFC 3164), and a file may mix vendors: `detect` says whose a file is.
- Each line as an `Entry`: vendor, line, time, kind (`TRAFFIC/end`, `traffic/forward`, `302013`), action, source and port, destination and port, protocol, user, application, rule, device, message; and every labelled value by name in `fields`. Lines that can't be read go to `problems`, never a panic.

## How it's checked

- Splunk's attack_data samples (Apache-2.0, `tests/fixtures/attack_data/`): PAN-OS TRAFFIC and THREAT logs (33 entries) and Cisco ASA logs (335 entries), every entry's main values as an independent Python oracle reads them (`tests/oracle/attack_data.tsv`, written by `tests/oracle/gen.py` from the vendors' documented field orders and wording).
- What the open samples lack, written for these tests after the vendors' documentation (`tests/fixtures/written/`): PAN-OS CONFIG, SYSTEM, GLOBALPROTECT and AUTHENTICATION lines and CSV exports, FortiGate `key=value` lines and a CSV download, and ASA messages of 18 ids the samples lack; read the same way (`tests/oracle/written.tsv`).
- Property tests: arbitrary bytes, lines glued from pieces of the three formats, and samples cut anywhere give entries, problems or nothing, never a panic.

## Not done yet

- PAN-OS's other log types (HIP match, User-ID, decryption, tunnel, …) are read by their common fields only, and its CEF and LEEF forwarding formats not at all.
- FortiGate's protocol stays a number (`6`); FortiAnalyzer's exports aren't read.
- ASA message ids not listed above are entries without their parts, and Firepower Threat Defense's `%FTD-` messages aren't read; a time from an RFC 3164 header alone has no year, so is left out.
- Times written in local time stay local: the firewall's zone isn't known.

## Licence

MIT or Apache-2.0, at your option.
