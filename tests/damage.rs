//! Any input gives entries, problems or nothing, never a panic.

use proptest::prelude::*;

/// Pieces of the three formats, glued in any order by the tests.
const FRAGMENTS: &[&str] = &[
    "671 ",
    "<14>",
    "<190>",
    "1 2024-02-22T12:32:26-05:00 PALO220 - - - - ",
    "Sep 14 23:42:50 host ",
    "Nov  7 09:07:15 fw ",
    ":2025-10-30T11:04:10Z: ",
    "Oct 30 2025 11:04:10 asa : ",
    "1,2024/02/22 12:32:26,012801036556,",
    "TRAFFIC,end,2305,2024/02/22 12:32:26,192.0.2.1,198.51.100.2,",
    "THREAT,url,",
    "CONFIG,0,",
    "GLOBALPROTECT,0,",
    "\"a,\"\"b\"\"\",",
    ",,,,",
    "2024-02-22T12:32:26.123+05:30,",
    "date=2024-01-05 ",
    "time=10:22:33 ",
    "eventtime=1704450153123456789 ",
    "eventtime=-99999999999999999999 ",
    "tz=\"+0100\" ",
    "logid=\"0000000013\" ",
    "type=\"traffic\" subtype=\"forward\" ",
    "msg=\"say \\\"hi\\\" ",
    "srcip=192.0.2.5 srcport=99999 ",
    "%ASA-6-302013: ",
    "%ASA-6-302014: ",
    "%ASA-5-111010: ",
    "%ASA-6-113005: ",
    "%ASA-6-722037: ",
    "%ASA-9-1234567: ",
    "Built inbound TCP connection 1 for a:192.0.2.1/1 (b/2) to c:198.51.100.2/3 (d/4)",
    "Teardown TCP connection 1 for a:b/c to d:e/f duration 0:00:01 bytes",
    "User 'admin', running 'CLI' from IP 192.0.2.1, executed '",
    "Group <g> User <u> IP <",
    "AAA user authentication Rejected : user IP = ",
    "access-list x denied tcp a/b( -> c/d(",
    "Uname: ",
    "é",
    "\u{feff}",
    "[x a=\"\\]\"]",
    "\n",
    "\r\n",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..1500)) {
        let _ = fwlogs::read(&data);
        let _ = fwlogs::detect(&data);
    }

    #[test]
    fn arbitrary_text(text in "[ -~\t\n\"<>=,:%/()\\[\\]]{0,600}") {
        let _ = fwlogs::read(text.as_bytes());
        let _ = fwlogs::detect(text.as_bytes());
    }

    #[test]
    fn lines_of_fragments(picks in proptest::collection::vec(0..FRAGMENTS.len(), 0..40)) {
        let text: String = picks.iter().map(|&at| FRAGMENTS[at]).collect();
        let _ = fwlogs::read(text.as_bytes());
        let _ = fwlogs::detect(text.as_bytes());
    }

    #[test]
    fn samples_cut_anywhere(cut in 0usize..2000) {
        let samples: [&[u8]; 5] = [
            include_bytes!("fixtures/written/panos-syslog.log"),
            include_bytes!("fixtures/written/panos-traffic-export.csv"),
            include_bytes!("fixtures/written/fortigate-kv.log"),
            include_bytes!("fixtures/written/fortigate-download.csv"),
            include_bytes!("fixtures/written/asa-syslog.log"),
        ];
        for sample in samples {
            let head = &sample[..cut.min(sample.len())];
            let _ = fwlogs::read(head);
            let _ = fwlogs::detect(head);
        }
    }
}

#[test]
fn damage_is_reported() {
    let log = fwlogs::read(
        b"%ASA-6-302013: Built sideways TCP connection 1 for a:192.0.2.1/1 to b:198.51.100.2/2\n\
          not a firewall line\n\
          %ASA-x\n\
          date=2024-01-05 time=10:22:33 logid=\"0000000013\" eventtime=soon type=\"traffic\"\n",
    );
    assert_eq!(log.entries.len(), 2);
    assert_eq!(
        log.problems,
        [
            "line 1: 302013: not worded as documented",
            "line 3: an %ASA- message not read",
            "line 4: eventtime \"soon\" not read",
            "line 2: no firewall log this crate reads",
        ]
    );
    // The entries keep what could be read.
    assert_eq!(log.entries[0].kind.as_deref(), Some("302013"));
    assert!(log.entries[1].time.is_some());
}
