"""Generates docs/data_source_schemas.drawio (open in draw.io / diagrams.net).

  python docs/gen_schema_drawio.py

Everything is read from the code, so the diagram cannot drift from it:
  schemas/01-05_*.schema.json   field lists, types, required / conditional fields, event keys, entity roles
  app/sources.py  wire()        the record Splunk actually stores for Defender and Entra (Event Hub wrappers)
  app/delivery  schedule()      the HEC envelope and its indexed fields
  schemas/06_*.schema.json      the ground-truth label record (never sent to Splunk)
"""
import asyncio
import html
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from xml.sax.saxutils import quoteattr

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
OUT = ROOT / "docs" / "data_source_schemas.drawio"
sys.path.insert(0, str(ROOT))

ROW, START, GAP, MAXH, PAD, HEAD = 20, 40, 26, 1500, 22, 128
CHAR_PX, MIN_W, MAX_W = 6.4, 330, 680
COLORS = {  # table header fill, stroke, panel fill
    "defender": ("#dae8fc", "#6c8ebf", "#f5f9ff"), "entra": ("#e1d5e7", "#9673a6", "#fbf8fd"),
    "cloudtrail": ("#ffe6cc", "#d79b00", "#fffaf3"), "windows": ("#d5e8d4", "#82b366", "#f6fbf5"),
    "firewall": ("#fff2cc", "#d6b656", "#fffbef"), "common": ("#f5f5f5", "#666666", "#ffffff"),
}
TYPE_NAMES = {"ts": "timestamp", "integer": "int", "boolean": "bool", "deviceId": "hex40", "gnull": "guid", "sidn": "sid",
              "uid": "object"}
ROLES = {  # x-role -> (badge, colour); entity roles are the fields that link events across sources
    "entity.user": ("user", "#0b63ce"), "entity.host": ("host", "#7b3fbf"), "entity.ip": ("ip", "#b4236d"),
    "entity.process": ("process", "#946200"), "entity.file_hash": ("hash", "#4d5a66"),
    "join_key.session": ("session", "#14803a"), "join_key.logon_session": ("session", "#14803a"),
    "join_key.process": ("process", "#946200"), "event_time": ("time", "#6b7785"),
}


# ----------------------------------------------------------------------------- JSON Schema reading

def deref(doc, s):
    """Follows $ref into doc's $defs, keeping local keys (x-role, description) and the first $def name."""
    s, name = dict(s), None
    while "$ref" in s:
        target = s.pop("$ref").rsplit("/", 1)[-1]
        name = name or target
        s = {**doc["$defs"][target], **s}
    if name:
        s["_ref"] = name
    return s


def collect(doc, s):
    """Properties and required names of an object schema, merging allOf members (if/then handled by callers)."""
    s = deref(doc, s)
    props, req = {}, set(s.get("required", []))
    for member in s.get("allOf", []):
        if "if" not in member:
            p, r = collect(doc, member)
            props.update(p)
            req |= r
    props.update(s.get("properties", {}))
    return props, req


def is_object(doc, s):
    s = deref(doc, s)
    return bool(s.get("properties") or any("if" not in m for m in s.get("allOf", [])))


def tlabel(doc, ps):
    s = deref(doc, ps)
    if "const" in s:
        return "string" if s["const"] == "" else f"= {s['const']}"
    if "enum" in s:
        vals = [str(v) for v in s["enum"] if v is not None]
        text = "|".join(vals)
        return ("enum(" + (text if len(text) <= 34 else "|".join(vals[:2]) + "|…") + ")") + ("?" if None in s["enum"] else "")
    for k in ("anyOf", "oneOf"):
        if k in s:
            parts = [tlabel(doc, m) for m in s[k]]
            nullable = "null" in parts or any(p.endswith("?") for p in parts)
            kinds = list(dict.fromkeys(p.rstrip("?") for p in parts if p != "null"))
            return "|".join(kinds) + ("?" if nullable else "")
    types = s.get("type", "object" if s.get("properties") else "any")
    types = types if isinstance(types, list) else [types]
    nullable = "null" in types
    kinds = [t for t in types if t != "null"]
    if s.get("_ref") and not s.get("properties") and len(kinds) <= 1:
        base = TYPE_NAMES.get(s["_ref"], s["_ref"])
    elif kinds == ["array"]:
        base = f"array<{tlabel(doc, s['items']) if 'items' in s else 'any'}>"
    else:
        base = "|".join(TYPE_NAMES.get(t, t) for t in kinds) or "null"
    return base + ("?" if nullable else "")


def roles_of(*schemas):
    out = []
    for s in schemas:
        r = s.get("x-role", [])
        out += r if isinstance(r, list) else [r]
    return list(dict.fromkeys(out))


def flatten(doc, s, prefix="", out=None):
    """One row per field, nested objects as dotted paths (arrays as name[].child)."""
    out = [] if out is None else out
    props, req = collect(doc, s)
    for name, ps in props.items():
        rs = deref(doc, ps)
        path = prefix + name
        out.append({"path": path, "type": tlabel(doc, ps), "req": "required" if name in req else "optional",
                    "roles": roles_of(ps, rs), "note": ""})
        if is_object(doc, rs):
            flatten(doc, rs, path + ".", out)
        elif rs.get("type") == "array" or "array" in (rs.get("type") or []):
            items = rs.get("items")
            if items and is_object(doc, items):
                flatten(doc, items, path + "[].", out)
    return out


def apply_conditions(doc, rows, schema):
    """Marks fields required only in some cases (allOf if/then) as conditional, with the condition as a note."""
    by_path = {r["path"]: r for r in rows}
    for clause in schema.get("allOf", []):
        if "if" not in clause:
            continue
        cond = describe_if(clause["if"])
        then = clause["then"]
        paths = list(then.get("required", []))
        for p, ps in then.get("properties", {}).items():
            paths += [f"{p}.{c}" for c in ps.get("required", [])]
            if p not in by_path and "type" in ps:  # property that only exists in this case
                rows.append({"path": p, "type": tlabel(doc, ps), "req": "optional", "roles": [], "note": ""})
                by_path[p] = rows[-1]
        for path in paths:
            r = by_path.get(path)
            if r is None:
                r = {"path": path, "type": "any", "req": "optional", "roles": [], "note": ""}
                rows.append(r)
                by_path[path] = r
            if r["req"] != "required":
                r["req"] = "conditional"
                r["note"] = f"when {cond}" if not r["note"] else r["note"] + f"; {cond}"


def describe_if(cond):
    parts = []
    for p, ps in cond.get("properties", {}).items():
        if "const" in ps:
            parts.append(f"{p}={ps['const']}")
        elif "enum" in ps:
            prefix = os.path.commonprefix(ps["enum"])
            parts.append(f"{p}={prefix}*" if len(prefix) >= 4 else f"{p} in {'/'.join(ps['enum'])}")
        for c, cs in ps.get("properties", {}).items():
            if "const" in cs:
                parts.append(f"{p}.{c}={cs['const']}")
    if not parts and cond.get("required"):
        parts = [f"{r} present" for r in cond["required"]]
    return " and ".join(parts)


def key_tokens(schema):
    return set(re.findall(r"[A-Za-z_][\w.]*", schema.get("x-dedupe-key", "")))


def mark_keys(rows, tokens):
    for r in rows:
        r["key"] = "dedupe_key" in r["roles"] or r["path"] in tokens
    return rows


def load(name):
    return json.loads((SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8"))


# ----------------------------------------------------------------------------- tables per source

def own_part(doc, variant):
    """The variant-specific allOf member (everything except the shared $ref base)."""
    v = deref(doc, variant)
    members = [m for m in v.get("allOf", []) if "$ref" not in m and "if" not in m]
    return members[0] if members else v


def value_type(v):
    return {str: "string", int: "int", float: "number", bool: "bool", dict: "object", list: "array"}.get(type(v), "any")


def wire_rows(record, inner_note, only_in=None):
    rows = []
    for k, v in record.items():
        note = inner_note if k == "properties" else ""
        if only_in and k in only_in:
            note = f"{only_in[k]} only"
        rows.append({"path": k, "type": value_type(v), "req": "required", "roles": [], "key": False, "note": note})
    return rows


def defender_tables():
    from app.generators.defender import generate_defender_baseline_event
    from app.registry.entities import use_tenant
    from app.sources import SOURCES
    doc = load("01_microsoft_defender")
    tok = key_tokens(doc)
    with use_tenant("tnt-acme"):
        record = SOURCES["Microsoft Defender"].wire(generate_defender_baseline_event())[0]
    tables = [("On the wire: Event Hub record", "what Splunk stores as _raw",
               wire_rows(record, "the Defender row (tables below)"))]
    tables.append(("Common to every table (deviceBase)", "all Advanced Hunting device tables",
                   mark_keys(flatten(doc, doc["$defs"]["deviceBase"]), tok)))
    for ref in doc["oneOf"]:
        v = deref(doc, ref)
        own = own_part(doc, ref)
        rows = mark_keys(flatten(doc, own), tok)
        sub = "+ common fields" if own is not v else "standalone (no device base)"
        tables.append((v.get("title", ref["$ref"]), sub, rows))
    return doc, tables


def entra_tables():
    from app.generators.entra import generate_entra_directory_audit_event, generate_entra_signin_event
    from app.registry.entities import use_tenant
    from app.sources import SOURCES
    doc = load("02_microsoft_entra_id")
    tok = key_tokens(doc) | {"id"}
    with use_tenant("tnt-acme"):
        signin = SOURCES["Microsoft Entra ID"].wire(generate_entra_signin_event("d.miller@acmefinancial.com", "198.51.100.14"))[0]
        audit = SOURCES["Microsoft Entra ID"].wire(generate_entra_directory_audit_event("d.miller@acmefinancial.com", "198.51.100.14"))[0]
    merged = {**audit, **signin}
    only = {k: "SignInLogs" for k in signin if k not in audit} | {k: "AuditLogs" for k in audit if k not in signin}
    tables = [("On the wire: Azure Monitor record", "category SignInLogs | AuditLogs",
               wire_rows(merged, "the Graph object (tables below)", only))]
    for ref in doc["oneOf"]:
        v = deref(doc, ref)
        tables.append((f"properties: {ref['$ref'].rsplit('/', 1)[-1]}", v.get("title", ""), mark_keys(flatten(doc, v), tok)))
    return doc, tables


def cloudtrail_tables():
    doc = load("03_aws_cloudtrail")
    rows = flatten(doc, doc)
    apply_conditions(doc, rows, doc)
    return doc, [("CloudTrail record", "stored in Splunk as-is", mark_keys(rows, key_tokens(doc)))]


def windows_tables():
    doc = load("04_windows_event_logs")
    tok = key_tokens(doc)
    pe = doc["properties"]["parsed_event"]
    header = [r for r in flatten(doc, pe) if r["path"] != "EventData"]
    header.insert(0, {"path": "raw_xml", "type": "string", "req": "required", "roles": [], "key": False,
                      "note": "the rendered <Event> XML = Splunk _raw"})
    tables = [("System header (every event)", "<Event><System> … </System>", mark_keys(header, tok))]
    for clause in deref(doc, pe).get("allOf", []) + pe.get("allOf", []):
        if "if" not in clause:
            continue
        p = clause["if"]["properties"]
        channel = p.get("Channel", {}).get("const", "")
        short = {"Microsoft-Windows-Sysmon/Operational": "Sysmon", "Microsoft-Windows-PowerShell/Operational": "PowerShell"}
        title = f"EventData · {short.get(channel, channel)} {p.get('EventID', {}).get('const', '')}"
        ed = clause["then"]["properties"]["EventData"]
        tables.append((title, channel, mark_keys(flatten(doc, ed), tok)))
    seen, unique = set(), []
    for t in tables:  # parsed_event's allOf may be reachable twice through the $ref merge
        if t[0] not in seen:
            seen.add(t[0])
            unique.append(t)
    return doc, unique


def firewall_tables():
    doc = load("05_firewall")
    tok = key_tokens(doc)
    top = [r for r in flatten(doc, {"properties": {k: v for k, v in doc["properties"].items() if k != "parsed_fields"},
                                    "required": doc["required"]})]
    for r in top:
        if r["path"] == "raw_message":
            r["note"] = "CEF:0|vendor|product|version|sig|name|sev|ext = Splunk _raw"
    parsed = doc["properties"]["parsed_fields"]
    return doc, [("Record", "only raw_message is sent", mark_keys(top, tok)),
                 ("parsed_fields (CEF decoded)", "cef ext: src dst spt dpt act rt suser cs1 cs2 …", mark_keys(flatten(doc, parsed), tok))]


def hec_rows():
    """Builds one real HEC item through the generator's own delivery code."""
    from app.config import settings
    from app.delivery import splunk_delivery as delivery
    from app.generators.cloudtrail import generate_cloudtrail_baseline_event
    from app.registry.entities import use_tenant
    with tempfile.TemporaryDirectory() as tmp:
        settings.GROUND_TRUTH_PATH = str(Path(tmp) / "gt.jsonl")
        for rate in ("FAULT_DUPLICATE_RATE", "FAULT_LATE_RATE", "FAULT_TRUNCATED_RATE", "FAULT_SCHEMA_DRIFT_RATE"):
            setattr(settings, rate, 0.0)
        with use_tenant("tnt-acme"):
            item = asyncio.run(delivery.schedule(generate_cloudtrail_baseline_event(), "AWS CloudTrail",
                                                 delivery.baseline_truth()))
    notes = {"time": "event time, epoch seconds", "event": "the payload (_raw): JSON object, XML or CEF line",
             "index": "security_endpoint | _identity | _cloud | _network"}
    rows = []
    for k, v in item.items():
        if k == "fields":
            rows += [{"path": f"fields.{f}", "type": "string", "req": "required", "roles": [], "key": f == "event_key",
                      "note": "HEC indexed field"} for f in v]
        else:
            typ = "object|string" if k == "event" else value_type(v)
            rows.append({"path": k, "type": typ, "req": "required", "roles": [], "key": False, "note": notes.get(k, "")})
    return rows


# ----------------------------------------------------------------------------- draw.io

class Drawio:
    def __init__(self):
        self.cells, self.n, self.boxes = [], 1, []

    def add(self, value, style, x, y, w, h, parent="1"):
        self.n += 1
        cid = f"c{self.n}"
        self.cells.append(f'<mxCell id="{cid}" value={quoteattr(value)} style="{style}" vertex="1" parent="{parent}">'
                          f'<mxGeometry x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" as="geometry"/></mxCell>')
        return cid

    def xml(self):
        return ('<mxfile host="gen_schema_drawio.py"><diagram name="Data source schemas" id="sources">'
                '<mxGraphModel grid="1" gridSize="10" page="0" math="0" shadow="0"><root><mxCell id="0"/>'
                '<mxCell id="1" parent="0"/>' + "".join(self.cells) + "</root></mxGraphModel></diagram></mxfile>")


def row_text(r):
    return f"{'K ' if r['key'] else ''}{r['path']} {r['type']} {' '.join(ROLES[x][0] for x in r['roles'] if x in ROLES)} {r['note']}"


def row_html(r):
    name = html.escape(r["path"])
    name = f"<b>{name}</b>" if r["req"] == "required" else f"<i>{name}</i>" if r["req"] == "conditional" else name
    badges = "".join(f' <font color="{ROLES[x][1]}">[{ROLES[x][0]}]</font>' for x in r["roles"] if x in ROLES)
    note = f' <font color="#9a9a9a">· {html.escape(r["note"])}</font>' if r["note"] else ""
    return f"{'&#128273; ' if r['key'] else ''}{name} <font color=\"#888888\">{html.escape(r['type'])}</font>{badges}{note}"


def table_width(title, sub, rows):
    longest = max([len(row_text(r)) for r in rows] + [len(title) * 1.2, len(sub)])
    return max(MIN_W, min(MAX_W, longest * CHAR_PX + 24))


def table(d, title, sub, rows, x, y, w, fill, stroke, dashed=False):
    style = (f"swimlane;fontStyle=1;childLayout=stackLayout;horizontal=1;startSize={START};horizontalStack=0;resizeParent=1;"
             f"resizeParentMax=0;resizeLast=0;collapsible=1;marginBottom=0;html=1;whiteSpace=wrap;fillColor={fill};"
             f"strokeColor={stroke};swimlaneFillColor=#ffffff;fontSize=12;" + ("dashed=1;" if dashed else ""))
    head = f"{html.escape(title)}<br><font style=\"font-size:10px;font-weight:normal\">{html.escape(sub)}</font>"
    tid = d.add(head, style, x, y, w, START + ROW * len(rows))
    rstyle = ("text;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;spacingLeft=6;spacingRight=4;"
              "overflow=hidden;rotatable=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;whiteSpace=nowrap;html=1;"
              "fontSize=11;fontFamily=Consolas;")
    for i, r in enumerate(rows):
        d.add(row_html(r), rstyle, 0, START + i * ROW, w, ROW, parent=tid)
    d.boxes.append((title, x, y, w, START + ROW * len(rows)))
    return tid


def panel(d, key, title, lines, tables, x0):
    fill, stroke, bg = COLORS[key]
    cols, cur, h = [], [], 0  # flow tables top-to-bottom into columns no taller than MAXH
    for t in tables:
        th = START + ROW * len(t[2])
        if cur and h + th > MAXH:
            cols.append(cur)
            cur, h = [], 0
        cur.append(t)
        h += th + GAP
    cols.append(cur)
    widths = [max(table_width(*t) for t in c) for c in cols]
    width = max(PAD * 2 + sum(widths) + GAP * (len(cols) - 1), 520)
    height = HEAD + max(sum(START + ROW * len(t[2]) + GAP for t in c) for c in cols) + PAD
    sub = "".join(f"<br><font style=\"font-size:11px;font-weight:normal\">{line}</font>" for line in lines)
    d.add(f"{html.escape(title)}{sub}", f"rounded=1;arcSize=1;whiteSpace=wrap;html=1;fillColor={bg};strokeColor={stroke};"
          "verticalAlign=top;align=left;spacingLeft=16;spacingRight=16;fontStyle=1;fontSize=16;spacingTop=8;", x0, 0, width, height)
    d.boxes.append((f"panel {title}", x0, 0, width, height))
    x = x0 + PAD
    for c, w in zip(cols, widths):
        y = HEAD
        for t in c:
            table(d, *t, x, y, w, fill, stroke)
            y += START + ROW * len(t[2]) + GAP
        x += w + GAP
    return width


def note(d, text, x, y, w, h, stroke="#999999"):
    d.add(text, f"rounded=1;whiteSpace=wrap;html=1;align=left;verticalAlign=top;spacing=10;fillColor=#ffffff;"
          f"strokeColor={stroke};fontSize=12;", x, y, w, h)
    d.boxes.append((text[:20], x, y, w, h))


def join_key_text(per_source):
    """Which field carries each entity in each source (from x-role): the fields that link events across sources."""
    lines = ["<b>Cross-source links</b> (fields tagged with an entity role in the schemas)"]
    for role in ("user", "host", "ip", "session", "process", "hash"):
        parts = []
        for src, rows in per_source.items():
            fields = list(dict.fromkeys(r["path"] for r in rows if any(ROLES.get(x, ("",))[0] == role for x in r["roles"])))
            if fields:
                shown = ", ".join(fields[:4]) + (f" +{len(fields) - 4}" if len(fields) > 4 else "")
                parts.append(f"<i>{src}</i>: {html.escape(shown)}")
        if parts:
            lines.append(f"<br><b><font color=\"{next(c for b, c in ROLES.values() if b == role)}\">[{role}]</font></b> "
                         + " · ".join(parts))
    plain = [re.sub(r"<[^>]+>", "", html.unescape(line)) for line in lines]
    return "".join(lines), sum(-(-len(line) // 58) for line in plain)  # wrapped lines at ~58 chars per 440 px


def main():
    d = Drawio()
    sources = [
        ("defender", "Microsoft Defender for Endpoint", defender_tables),
        ("entra", "Microsoft Entra ID", entra_tables),
        ("cloudtrail", "AWS CloudTrail", cloudtrail_tables),
        ("windows", "Windows Event Logs (Security · Sysmon · PowerShell)", windows_tables),
        ("firewall", "Network Firewall (CEF)", firewall_tables),
    ]
    # column 0: what every source shares on the way to Splunk, and the labels kept beside it
    fill, stroke, _ = COLORS["common"]
    hec = hec_rows()
    w0 = max(table_width("HEC event (every source)", "", hec), 440)
    table(d, "HEC event (every source)", "POST /services/collector/event · useACK", hec, 0, 0, w0, fill, stroke)
    y = START + ROW * len(hec) + GAP
    gt_doc = load("06_ground_truth_labels")
    gt = mark_keys(flatten(gt_doc, gt_doc), key_tokens(gt_doc) | {"delivery_id"})
    table(d, "Ground-truth label (NEVER sent to Splunk)", "out/ground_truth.jsonl · join on delivery_id",
          gt, 0, y, w0, "#f8cecc", "#b85450", dashed=True)
    y += START + ROW * len(gt) + GAP
    legend = ("<b>Legend</b><br>&#128273; event key (deduplication)<br><b>bold</b> required<br><i>italic</i> conditional "
              "(see note)<br>plain optional<br>grey = type · ? = nullable<br>[user] [host] [ip] … entity role: links events "
              "across sources")
    note(d, legend, 0, y, w0, 140)
    y += 140 + GAP

    x, per_source = w0 + 60, {}
    for key, title, build in sources:
        doc, tables = build()
        xs = doc["x-splunk"]
        lines = [f"Splunk index <b>{xs['index']}</b> · sourcetype <b>{xs['sourcetype_simulation']}</b>",
                 f"Event key: {html.escape(doc.get('x-dedupe-key', ''))}",
                 html.escape(xs.get("delivery", ""))[:170]]
        if key == "windows":
            lines.append("Event IDs without a typed table (e.g. 4672) are accepted with generic EventData.")
        x += panel(d, key, title, lines, tables, x) + 60
        per_source[title.split(" (")[0]] = [r for _, _, rows in tables for r in rows]

    text, n = join_key_text(per_source)
    note(d, text, 0, y, w0, 30 + n * 17, stroke="#6c8ebf")

    OUT.write_text(d.xml(), encoding="utf-8")
    return d


if __name__ == "__main__":
    out = main()
    print(f"wrote {OUT} ({len(out.cells)} cells, {len(out.boxes)} boxes)")
