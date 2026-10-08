//! Every entry of the fixtures, its main values as the independent Python
//! oracle reads them (`tests/oracle/*.tsv`, written by
//! `tests/oracle/gen.py`, see `tests/oracle/README`): Splunk's `attack_data`
//! samples (Apache-2.0, `tests/fixtures/attack_data/`) and samples written
//! for these tests after the vendors' documentation
//! (`tests/fixtures/written/`).

use fwlogs::Entry;

/// Tabs and line breaks as the oracle writes them.
fn escape(text: &str) -> String {
    text.replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn line(name: &str, entry: &Entry) -> String {
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    let port = |value: Option<u16>| value.map(|p| p.to_string()).unwrap_or_default();
    let cells = [
        name.to_owned(),
        entry.line.to_string(),
        entry.vendor.name().to_owned(),
        text(&entry.kind),
        entry.time.and_then(|t| t.to_iso8601()).unwrap_or_default(),
        text(&entry.action),
        text(&entry.source),
        port(entry.source_port),
        text(&entry.destination),
        port(entry.destination_port),
        text(&entry.protocol),
        text(&entry.user),
        text(&entry.application),
        text(&entry.rule),
        text(&entry.device),
        text(&entry.message),
    ];
    cells.map(|cell| escape(&cell)).join("\t")
}

/// Every file of `folder` read, its entries as lines.
fn read_folder(folder: &str) -> Vec<String> {
    let folder = format!("{}/tests/fixtures/{folder}", env!("CARGO_MANIFEST_DIR"));
    let mut names: Vec<String> = std::fs::read_dir(&folder)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n != "NOTICE" && n != "LICENSE")
        .collect();
    names.sort();
    let mut got = Vec::new();
    for name in &names {
        let data = std::fs::read(format!("{folder}/{name}")).unwrap();
        assert!(fwlogs::detect(&data).is_some(), "{name}");
        let log = fwlogs::read(&data);
        assert_eq!(log.problems, Vec::<String>::new(), "{name}");
        got.extend(log.entries.iter().map(|e| line(name, e)));
    }
    got
}

fn assert_same(got: &[String], oracle: &str) {
    let expected: Vec<&str> = oracle.lines().collect();
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
}

#[test]
fn open_samples_as_the_oracle_reads_them() {
    assert_same(
        &read_folder("attack_data"),
        include_str!("oracle/attack_data.tsv"),
    );
}

#[test]
fn written_samples_as_the_oracle_reads_them() {
    assert_same(&read_folder("written"), include_str!("oracle/written.tsv"));
}
