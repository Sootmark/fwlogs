"""Writes the oracle TSVs: the main values of every entry of the firewall
logs in a fixtures folder, read with Python's own csv and re modules, the
PAN-OS field orders as Palo Alto documents them (PAN-OS 11.1, "Format:"),
FortiGate's keys and the ASA's message wording as their vendors document
them. One line per entry: the file, the line, the vendor, the kind, the
time (ISO 8601 to 100 ns; UTC with Z, local without), the action, source,
source port, destination, destination port, protocol, user, application,
rule, device and message. Tabs and line breaks in values are written \\t,
\\n, \\r. Independent of this crate: no code shared.

Run: python3 -I tests/oracle/gen.py tests/fixtures/attack_data > tests/oracle/attack_data.tsv
     python3 -I tests/oracle/gen.py tests/fixtures/written > tests/oracle/written.tsv
"""

import calendar
import csv
import datetime
import io
import pathlib
import re
import sys

# The "Format:" lists of PAN-OS 11.1's syslog field descriptions.
PAN_FORMATS = {
    "TRAFFIC": """
        FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type,
        FUTURE_USE, Generated Time, Source Address, Destination Address, NAT
        Source IP, NAT Destination IP, Rule Name, Source User, Destination
        User, Application, Virtual System, Source Zone, Destination Zone,
        Inbound Interface, Outbound Interface, Log Action, FUTURE_USE,
        Session ID, Repeat Count, Source Port, Destination Port, NAT Source
        Port, NAT Destination Port, Flags, Protocol, Action, Bytes, Bytes
        Sent, Bytes Received, Packets, Start Time, Elapsed Time, Category,
        FUTURE_USE, Sequence Number, Action Flags, Source Country,
        Destination Country, FUTURE_USE, Packets Sent, Packets Received,
        Session End Reason, Device Group Hierarchy Level 1, Device Group
        Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group
        Hierarchy Level 4, Virtual System Name, Device Name, Action Source,
        Source VM UUID, Destination VM UUID, Tunnel ID/IMSI, Monitor
        Tag/IMEI, Parent Session ID, Parent Start Time, Tunnel Type, SCTP
        Association ID, SCTP Chunks, SCTP Chunks Sent, SCTP Chunks Received,
        Rule UUID, HTTP/2 Connection, App Flap Count, Policy ID, Link
        Switches, SD-WAN Cluster, SD-WAN Device Type, SD-WAN Cluster Type,
        SD-WAN Site, Dynamic User Group Name, XFF Address, Source Device
        Category, Source Device Profile, Source Device Model, Source Device
        Vendor, Source Device OS Family, Source Device OS Version, Source
        Hostname, Source Mac Address, Destination Device Category,
        Destination Device Profile, Destination Device Model, Destination
        Device Vendor, Destination Device OS Family, Destination Device OS
        Version, Destination Hostname, Destination Mac Address, Container
        ID, POD Namespace, POD Name, Source External Dynamic List,
        Destination External Dynamic List, Host ID, Serial Number, Source
        Dynamic Address Group, Destination Dynamic Address Group, Session
        Owner, High Resolution Timestamp, A Slice Service Type, A Slice
        Differentiator, Application Subcategory, Application Category,
        Application Technology, Application Risk, Application
        Characteristic, Application Container, Tunneled Application,
        Application SaaS, Application Sanctioned State, Offloaded, Flow
        Type, Cluster Name, AI Traffic, AI Forward Error, K8S Cluster ID,
        tcp_rtt_c2s, tcp_rtt_s2c, total_n_ooseq_c2s, total_n_ooseq_s2c,
        tcp_retransit_cnt_c2s, tcp_retransit_cnt_s2c,
        tcp_zero_window_cnt_c2s, tcp_zero_window_cnt_s2c, Source Adv DevID,
        Destination Adv DevID
    """,
    "THREAT": """
        FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type,
        FUTURE_USE, Generated Time, Source Address, Destination Address, NAT
        Source IP, NAT Destination IP, Rule Name, Source User, Destination
        User, Application, Virtual System, Source Zone, Destination Zone,
        Inbound Interface, Outbound Interface, Log Action, FUTURE_USE,
        Session ID, Repeat Count, Source Port, Destination Port, NAT Source
        Port, NAT Destination Port, Flags, IP Protocol, Action,
        URL/Filename, Threat ID, Category, Severity, Direction, Sequence
        Number, Action Flags, Source Location, Destination Location,
        FUTURE_USE, Content Type, PCAP_ID, File Digest, Cloud, URL Index,
        User Agent, File Type, X-Forwarded-For, Referer, Sender, Subject,
        Recipient, Report ID, Device Group Hierarchy Level 1, Device Group
        Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group
        Hierarchy Level 4, Virtual System Name, Device Name, FUTURE_USE,
        Source VM UUID, Destination VM UUID, HTTP Method, Tunnel ID/IMSI,
        Monitor Tag/IMEI, Parent Session ID, Parent Start Time, Tunnel Type,
        Threat Category, Content Version, FUTURE_USE, SCTP Association ID,
        Payload Protocol ID, HTTP Headers, URL Category List, Rule UUID,
        HTTP/2 Connection, Dynamic User Group Name, XFF Address, Source
        Device Category, Source Device Profile, Source Device Model, Source
        Device Vendor, Source Device OS Family, Source Device OS Version,
        Source Hostname, Source MAC Address, Destination Device Category,
        Destination Device Profile, Destination Device Model, Destination
        Device Vendor, Destination Device OS Family, Destination Device OS
        Version, Destination Hostname, Destination MAC Address, Container
        ID, POD Namespace, POD Name, Source External Dynamic List,
        Destination External Dynamic List, Host ID, Serial Number, Domain
        EDL, Source Dynamic Address Group, Destination Dynamic Address
        Group, Partial Hash, High Resolution Timestamp, Reason,
        Justification, A Slice Service Type, Application Subcategory,
        Application Category, Application Technology, Application Risk,
        Application Characteristic, Application Container, Tunneled
        Application, Application SaaS, Application Sanctioned State, Cloud
        Report ID, Flow Type, Cluster Name
    """,
    "CONFIG": """
        FUTURE_USE, Receive Time, Serial Number, Type, Subtype, FUTURE_USE,
        Generated Time, Host, Virtual System, Command, Admin, Client,
        Result, Configuration Path, Before Change Detail, After Change
        Detail, Sequence Number, Action Flags, Device Group Hierarchy Level
        1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3,
        Device Group Hierarchy Level 4, Virtual System Name, Device Name,
        Device Group, Audit Comment, FUTURE_USE, High Resolution Timestamp
    """,
    "SYSTEM": """
        FUTURE_USE, Receive Time, Serial Number, Type, Content/Threat Type,
        FUTURE_USE, Generated Time, Virtual System, Event ID, Object,
        FUTURE_USE, FUTURE_USE, Module, Severity, Description, Sequence
        Number, Action Flags, Device Group Hierarchy Level 1, Device Group
        Hierarchy Level 2, Device Group Hierarchy Level 3, Device Group
        Hierarchy Level 4, Virtual System Name, Device Name, FUTURE_USE,
        FUTURE_USE, High Resolution Timestamp
    """,
    "GLOBALPROTECT": """
        FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type,
        FUTURE_USE, Generated Time, Virtual System, Event ID, Stage,
        Authentication Method, Tunnel Type, Source User, Source Region,
        Machine Name, Public IP, Public IPv6, Private IP, Private IPv6, Host
        ID, Serial Number, Client Version, Client OS, Client OS Version,
        Repeat Count, Reason, Error, Description, Status, Location, Login
        Duration, Connect Method, Error Code, Portal, Sequence Number,
        Action Flags, High Res Timestamp, Selection Type, Response Time,
        Priority, Attempted Gateways, Gateway, Device Group Hierarchy Level
        1, Device Group Hierarchy Level 2, Device Group Hierarchy Level 3,
        Device Group Hierarchy Level 4, Virtual System Name, Device Name,
        Virtual System ID, Cluster Name
    """,
    "AUTHENTICATION": """
        FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type,
        FUTURE_USE, Generated Time, Virtual System, Source IP, User,
        Normalize User, Object, Authentication Policy, Repeat Count,
        Authentication ID, Vendor, Log Action, Server Profile, Description,
        Client Type, Event Type, Factor Number, Sequence Number, Action
        Flags, Device Group Hierarchy 1, Device Group Hierarchy 2, Device
        Group Hierarchy 3, Device Group Hierarchy 4, Virtual System Name,
        Device Name, Virtual System ID, Authentication Protocol, UUID for
        rule, High Resolution Timestamp, Source Device Category, Source
        Device Profile, Source Device Model, Source Device Vendor, Source
        Device OS Family, Source Device OS Version, Source Hostname, Source
        Mac Address, Region, FUTURE_USE, User Agent, Session ID, Cluster
        Name
    """,
}
PAN = {kind: [name.strip() for name in re.sub(r"\s+", " ", text).split(",")]
       for kind, text in PAN_FORMATS.items()}
PAN_COMMON = PAN["TRAFFIC"][:7]

MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
ISO = (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
       r"(?:[Zz]|[+-]\d{2}(?::?\d{2})?)?")
TICKS = 10_000_000


# Times, as ticks (100 ns) since 1970 and whether UTC.

def wall(year, month, day, hour, minute, second):
    try:
        datetime.datetime(year, month, day, hour, minute, min(second, 59))
    except ValueError:
        return None
    return calendar.timegm((year, month, day, hour, minute, second)) * TICKS


def iso(text):
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?"
                     r"([Zz]|[+-]\d{2}(?::?\d{2})?)?", text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, fraction, zone = m.groups()
    ticks = wall(int(y), int(mo), int(d), int(h), int(mi), int(s))
    if ticks is None:
        return None
    ticks += int((fraction or "")[:7].ljust(7, "0"))
    if not zone:
        return ticks, False
    return ticks - offset(zone) * 60 * TICKS, True


def offset(zone):
    if zone in "Zz":
        return 0
    digits = zone[1:].replace(":", "")
    minutes = int(digits[:2]) * 60 + int(digits[2:] or 0)
    return -minutes if zone[0] == "-" else minutes


def local(date, clock, separator):
    dm = re.fullmatch(rf"(\d{{4}}){separator}(\d{{1,2}}){separator}(\d{{1,2}})", date.strip())
    cm = re.fullmatch(r"(\d{1,2}):(\d{2}):(\d{2})", clock.strip())
    if not dm or not cm:
        return None
    ticks = wall(*map(int, dm.groups()), *map(int, cm.groups()))
    return None if ticks is None else (ticks, False)


def epoch(text):
    value = int(text)
    size = abs(value)
    if size < 10**11:
        ticks = value * TICKS
    elif size < 10**14:
        ticks = value * 10_000
    elif size < 10**17:
        ticks = value * 10
    else:
        ticks = value // 100
    return (ticks, True) if value else None


def written(time):
    if time is None:
        return ""
    ticks, utc = time
    moment = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=ticks // 10)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ticks % TICKS:07d}" + ("Z" if utc else "")


# Syslog headers.

def header(line):
    """The header's time text, time (when zoned), host, and the rest."""
    rest = line.lstrip()
    rest = re.sub(r"^\d+ (?=<)", "", rest)
    rest = re.sub(r"^<\d{1,3}>", "", rest)
    m = re.match(rf"\d{{1,2}} (-|{ISO}) (\S+) \S+ \S+ \S+ (?:-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: |$)", rest)
    if m:
        stamp, host = m.group(1), m.group(2)
        return (None if stamp == "-" else stamp, None if stamp == "-" else iso(stamp),
                None if host == "-" else host, rest[m.end():])
    m = re.match(rf"({ISO}) ([^ ]+)(?: |$)", rest)
    if m and is_host(m.group(2)):
        return m.group(1), iso(m.group(1)), m.group(2), rest[m.end():]
    m = re.match(rf"((?:{'|'.join(MONTHS)}) +\d{{1,2}} \d{{1,2}}:\d{{2}}:\d{{2}}) ([^ ]+)(?: |$)", rest)
    if m and is_host(m.group(2)):
        return m.group(1), None, m.group(2), rest[m.end():]
    return None, None, None, rest


def is_host(word):
    return "," not in word and "=" not in word and not word.startswith(":") and not word.endswith(":")


def normalised(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def first(fields, *names):
    for name in names:
        for key, value in fields:
            if normalised(key) == name:
                return value
    return None


def port(text):
    return text if text and text.isdigit() and int(text) < 65536 else None


def entry(vendor, kind, time, fields, main, message):
    """A line of the TSV; `main` gives each value's candidate names."""
    values = [first(fields, *names) for names in main]
    for at in (2, 4):
        values[at] = port(values[at])
    if message is not None:
        values[-1] = message
    return [vendor, kind, written(time)] + values


def with_header(stamp, host):
    return [(n, v) for n, v in (("syslog_time", stamp), ("syslog_host", host)) if v]


def put(fields, name, value):
    value = (value or "").strip()
    if value:
        fields.append((name, value))


# PAN-OS.

PAN_MAIN = [
    ["action", "result", "status", "eventtype"],
    ["sourceaddress", "sourceip", "publicip", "host"],
    ["sourceport"],
    ["destinationaddress"],
    ["destinationport"],
    ["protocol", "ipprotocol"],
    ["sourceuser", "user", "admin"],
    ["application"],
    ["rulename", "rule", "authenticationpolicy"],
    ["devicename", "serialnumber", "serial", "sysloghost"],
    ["description", "configurationpath", "urlfilename", "threatid", "threatcontentname"],
]


def pan(fields, header_time):
    kind = first(fields, "type")
    subtype = first(fields, "threatcontenttype", "contentthreattype", "subtype")
    if kind and subtype:
        kind = f"{kind}/{subtype}"
    time = None
    zoned = first(fields, "highresolutiontimestamp", "highrestimestamp")
    if zoned:
        time = iso(zoned)
    generated = first(fields, "generatedtime", "generatetime")
    if time is None and generated:
        date, _, clock = generated.partition(" ")
        time = local(date, clock, "/")
    return entry("panos", kind, time or header_time, fields, PAN_MAIN, None)


def pan_line(line):
    m = re.search(r"(?:^|(?<= ))\d*,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},", line)
    if not m:
        return None
    row = next(csv.reader([line[m.start():]]))
    if len(row) < 4 or not re.fullmatch(r"[A-Z]+", row[3]):
        return None
    stamp, header_time, host, _ = header(line[:m.start()])
    names = PAN.get(row[3], PAN_COMMON)
    fields = with_header(stamp, host)
    for index, value in enumerate(row):
        name = names[index] if index < len(names) else f"Field {index}"
        if name != "FUTURE_USE":
            put(fields, name, value)
    return pan(fields, header_time)


def pan_export(text):
    reader = csv.reader(io.StringIO(text))
    names = next(reader)
    lines = []
    start = reader.line_num + 1
    for row in reader:
        if any(row):
            fields = []
            for index, value in enumerate(row):
                name = names[index].strip() if index < len(names) and names[index].strip() else f"Field {index}"
                put(fields, name, value)
            lines.append((start, pan(fields, None)))
        start = reader.line_num + 1
    return lines


def is_export(text):
    line = next((l for l in text.splitlines() if l.strip()), "")
    names = [normalised(c) for c in next(csv.reader([line]), [])]
    return "receivetime" in names and "type" in names


# FortiGate.

FORTI_MAIN = [
    ["action", "status"],
    ["srcip", "remip"],
    ["srcport"],
    ["dstip"],
    ["dstport"],
    ["proto"],
    ["user", "unauthuser"],
    ["app", "service"],
    ["policyname", "policyid"],
    ["devname", "devid", "sysloghost"],
    ["msg", "logdesc"],
]
PAIR = re.compile(r'([^=\s,]+)=(?:"((?:[^"\\]|\\.)*)"|([^\s,]*))')


def unescape(text):
    return re.sub(r'\\(["\\])', r"\1", text)


def forti_pairs(body):
    first_pair = PAIR.search(body)
    is_csv = body.lstrip().startswith('"') or (first_pair and body[first_pair.end():].startswith(","))
    if not is_csv:
        return [(m.group(1), unescape(m.group(2)) if m.group(2) is not None else m.group(3))
                for m in PAIR.finditer(body)]
    pairs = []
    for cell in next(csv.reader([body])):
        key, equals, value = cell.partition("=")
        value = value.strip()
        if equals and key.strip():
            if value.startswith('"'):
                value = unescape(re.match(r'"((?:[^"\\]|\\.)*)', value).group(1))
            pairs.append((key.strip(), value))
    return pairs


def forti_line(line):
    stamp, header_time, host, body = header(line)
    pairs = forti_pairs(body)
    keys = {k for k, _ in pairs}
    if "logid" not in keys and not ("type" in keys and keys & {"devname", "devid"}):
        return None
    fields = with_header(stamp, host)
    for key, value in pairs:
        put(fields, key, value)
    values = dict(reversed(fields))
    kind = values.get("type")
    if kind and values.get("subtype"):
        kind += "/" + values["subtype"]
    time = None
    if "eventtime" in values:
        time = epoch(values["eventtime"])
    elif "date" in values and "time" in values:
        time = local(values["date"], values["time"], "-")
        if time and re.fullmatch(r"[+-]\d{2}(?::?\d{2})?", values.get("tz", "")):
            time = (time[0] - offset(values["tz"]) * 60 * TICKS, True)
    return entry("fortigate", kind, time or header_time, fields, FORTI_MAIN, None)


# Cisco ASA.

ASA_MAIN = [["action"], ["source"], ["sourceport"], ["destination"], ["destinationport"], ["protocol"],
            ["user"], ["application"], ["rule"], ["device"], []]


def end(text):
    """`address/port` or `address/service` as (address, port, service)."""
    address, _, after = text.partition("/")
    return (address, after, None) if after.isdigit() else (address, None, after or None)


def asa_parts(id, text):
    """The main values of a message, by id, as Cisco words it."""
    p = {}
    if id in ("302013", "302015"):
        m = re.match(r"Built (inbound|outbound) (\S+) connection \S+ for [^:\s]+:(\S+) \(\S+\)"
                     r"(?: \([^)]*\))? to [^:\s]+:(\S+) \(", text)
        first_end, second_end = end(m.group(3)), end(m.group(4))
        source, destination = (first_end, second_end) if m.group(1) == "inbound" else (second_end, first_end)
        p.update(action="built", protocol=m.group(2), source=source[0], sourceport=source[1],
                 destination=destination[0], destinationport=destination[1])
    elif id in ("302014", "302016"):
        m = re.match(r"Teardown (\S+) connection \S+ for \S+ to \S+ ", text)
        p.update(action="teardown", protocol=m.group(1))
    elif id == "106023":
        m = re.match(r'Deny (\S+) src [^:\s]+:([^/\s]+)(?:/(\S+))? dst [^:\s]+:([^/\s]+)(?:/(\S+))? .*'
                     r'by access-group "?([^"\s]+)"?', text)
        p.update(action="deny", protocol=m.group(1), source=m.group(2), sourceport=m.group(3),
                 destination=m.group(4), destinationport=m.group(5), rule=m.group(6))
    elif id == "106100":
        m = re.match(r"access-list (\S+) (\S+) (\S+) [^/\s]+/([^(\s]+)\((\d+)\) -> [^/\s]+/([^(\s]+)\((\d+)\)", text)
        p.update(rule=m.group(1), action=m.group(2), protocol=m.group(3), source=m.group(4),
                 sourceport=m.group(5), destination=m.group(6), destinationport=m.group(7))
    elif id == "106015":
        m = re.match(r"Deny (\S+) \(no connection\) from (\S+) to (\S+) flags", text)
        source, destination = end(m.group(2)), end(m.group(3))
        p.update(action="deny", protocol=m.group(1), source=source[0], sourceport=source[1],
                 destination=destination[0], destinationport=destination[1])
    elif id == "710005":
        m = re.match(r"(\S+) request discarded from (\S+) to [^:\s]+:(\S+)", text)
        source, destination = end(m.group(2)), end(m.group(3))
        p.update(action="discarded", protocol=m.group(1), source=source[0], sourceport=source[1],
                 destination=destination[0], destinationport=destination[1], application=destination[2])
    elif id == "609002":
        assert text.startswith("Teardown local-host ")
        p.update(action="teardown")
    elif id in ("113004", "113005", "113015"):
        m = re.match(r"AAA user \S+ (\S+)", text)
        user = re.search(r" : user = (.+?)(?: : |$)", text)
        address = re.search(r" : user IP = (\S+)", text)
        p.update(action=m.group(1).lower(), user=user and user.group(1).strip(),
                 source=address and address.group(1))
    elif id in ("113039", "716001", "716002", "722022", "722023", "722037"):
        m = re.match(r"Group <([^>]*)> User <([^>]*)> IP <([^>]*)> (.*)$", text)
        rest = m.group(4)
        verb = next(v for v in ("started", "established", "terminated", "closing") if v in rest)
        protocol = rest.split()[0] if rest.split()[0] in ("TCP", "UDP") else None
        p.update(action=verb, user=m.group(2), source=m.group(3), protocol=protocol)
    elif id in ("605004", "605005"):
        m = re.match(r'Login (\w+) from (\S+) to [^:\s]+:(\S+) for user "(.*)"$', text)
        source, destination = end(m.group(2)), end(m.group(3))
        p.update(action=m.group(1), source=source[0], sourceport=source[1], destination=destination[0],
                 destinationport=destination[1], application=destination[2], user=m.group(4))
    elif id == "611103":
        p.update(action="logged out", user=re.search(r"Uname: (\S+)", text).group(1))
    elif id == "111008":
        m = re.match(r"User '([^']*)' executed the '.*' command\.?$", text)
        p.update(action="executed", user=m.group(1))
    elif id == "111009":
        m = re.match(r"User '([^']*)' executed cmd:", text)
        p.update(action="executed", user=m.group(1))
    elif id == "111010":
        m = re.match(r"User '([^']*)', running '([^']*)' from IP ([^,\s]+), executed ", text)
        p.update(action="executed", user=m.group(1), application=m.group(2), source=m.group(3))
    elif id in ("502101", "502102", "502103"):
        verb = next(v for v in ("added", "deleted", "changed") if v in text.split(":")[0])
        p.update(action=verb, user=re.search(r"Uname: (\S+)", text).group(1))
    return p


def asa_line(line):
    m = re.search(r"%ASA-([0-7])-(\d{1,6}):(.*)$", line)
    if not m:
        return None
    stamp, header_time, host, rest = header(line[:m.start()])
    time, device = None, None
    words = [w.strip(":") for w in rest.split() if w.strip(":")]
    at = 0
    while at < len(words):
        legacy = words[at:at + 4]
        if iso(words[at]):
            time, at = iso(words[at]), at + 1
        elif (len(legacy) == 4 and legacy[0] in MONTHS
              and local(f"{legacy[2]}-{MONTHS.index(legacy[0]) + 1}-{legacy[1]}", legacy[3], "-")):
            time = local(f"{legacy[2]}-{MONTHS.index(legacy[0]) + 1}-{legacy[1]}", legacy[3], "-")
            at += 4
        else:
            device, at = words[at], at + 1
    text = m.group(3).strip()
    parts = asa_parts(m.group(2), text)
    parts["device"] = device or host
    fields = [(name, value) for name, value in parts.items() if value]
    return entry("asa", m.group(2), time or header_time, fields, ASA_MAIN, text or None)


def lines_of(text):
    if is_export(text):
        return pan_export(text)
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.rstrip("\r")
        if line.strip():
            read = asa_line(line) or pan_line(line) or forti_line(line)
            assert read, f"line {number} not read"
            out.append((number, read))
    return out


def main(folder):
    out = []
    for path in sorted(pathlib.Path(folder).iterdir()):
        if path.name in ("NOTICE", "LICENSE"):
            continue
        text = path.read_bytes().decode("utf-8", "replace").lstrip("\ufeff")
        for number, values in lines_of(text):
            cells = [path.name, str(number)] + [v or "" for v in values]
            out.append("\t".join(c.replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r") for c in cells))
    print("\n".join(out))


main(sys.argv[1])
