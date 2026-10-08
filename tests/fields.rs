//! Labelled values beyond the main ones, kept by name.

use fwlogs::{Entry, Vendor};

fn read(folder: &str, name: &str) -> Vec<Entry> {
    let path = format!(
        "{}/tests/fixtures/{folder}/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let log = fwlogs::read(&std::fs::read(path).unwrap());
    assert_eq!(log.problems, Vec::<String>::new());
    log.entries
}

#[test]
fn panos_fields_by_documented_name() {
    let entries = read("attack_data", "pan_tor_allowed.log");
    let tor = &entries[0];
    assert_eq!(tor.vendor, Vendor::PaloAlto);
    assert_eq!(tor.get("Serial Number"), Some("016201005228"));
    assert_eq!(tor.get("Session End Reason"), Some("aged-out"));
    assert_eq!(tor.get("Bytes Sent"), Some("438"));
    assert_eq!(tor.get("syslog_host"), Some("victim_domain.com"));
    assert_eq!(tor.get("syslog_time"), Some("Sep 14 23:42:50"));
    assert_eq!(
        tor.get("Application Characteristic"),
        Some("evasive-behavior,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,prone-to-misuse")
    );
    let entries = read("written", "panos-syslog.log");
    let change = &entries[0];
    assert_eq!(change.get("Command"), Some("edit"));
    assert_eq!(
        change.get("After Change Detail"),
        Some("action: allow, log-end: yes")
    );
    let hip = &entries[8];
    assert_eq!(hip.kind.as_deref(), Some("HIPMATCH/0"));
    assert_eq!(hip.get("Field 7"), Some("alice"));
}

#[test]
fn panos_export_columns_by_name() {
    let entries = read("written", "panos-threat-export.csv");
    assert_eq!(entries[0].line, 2);
    assert_eq!(
        entries[0].get("URL/Filename"),
        Some("invoice \"March\".exe")
    );
    assert_eq!(entries[1].get("Severity"), Some("critical"));
    assert_eq!(
        entries[1].message.as_deref(),
        Some("Apache Log4j Remote Code Execution Vulnerability(91991)")
    );
}

#[test]
fn fortigate_keys() {
    let entries = read("written", "fortigate-kv.log");
    let virus = &entries[6];
    assert_eq!(virus.get("virus"), Some("EICAR_TEST_FILE"));
    assert_eq!(
        virus.get("url"),
        Some("http://198.51.100.80/files/eicar.com")
    );
    let login = &entries[2];
    assert_eq!(login.get("status"), Some("failed"));
    assert_eq!(login.get("syslog_host"), Some("fg100e-edge"));
    let entries = read("written", "fortigate-download.csv");
    assert_eq!(entries[2].get("catdesc"), Some("Newly Observed Domain"));
}

#[test]
fn asa_message_parts() {
    let entries = read("written", "asa-syslog.log");
    let teardown = &entries[3];
    assert_eq!(teardown.get("first_address"), Some("198.51.100.200"));
    assert_eq!(teardown.get("second_interface"), Some("inside"));
    assert_eq!(teardown.get("duration"), Some("0:00:31"));
    assert_eq!(teardown.get("bytes"), Some("48213"));
    assert_eq!(teardown.get("reason"), Some("TCP FINs"));
    assert_eq!(teardown.get("teardown_initiator"), Some("inside"));
    assert_eq!(teardown.get("severity"), Some("6"));
    let session = &entries[15];
    assert_eq!(session.get("group"), Some("GP-Staff"));
    assert_eq!(session.get("reason"), Some("User Requested"));
    let command = &entries[20];
    assert_eq!(
        command.get("command"),
        Some("username backup password ***** privilege 15")
    );
    let added = &entries[21];
    assert_eq!(added.get("priv"), Some("15"));
    let denied = &entries[18];
    assert_eq!(denied.get("destination_service"), Some("ssh"));
    let entries = read("attack_data", "asa_generic.log");
    let changed = &entries[2];
    assert_eq!(
        (changed.get("from"), changed.get("to")),
        (Some("2"), Some("14"))
    );
}
