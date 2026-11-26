"""Generates docs/sample_specs_schemas.drawio: the schema the sample_specs/*.json records actually use.

  python docs/gen_sample_specs_drawio.py

The sample files hold example records, not schemas, so the schema is inferred from them: every field seen in a
family, its type from the values, whether every record of that family has it ("in n/m" when not), one example
value, and the identifiers that recur across sources (how the samples link up). Event keys come from schemas/.
Same look as docs/data_source_schemas.drawio (drawing helpers are shared with gen_schema_drawio.py).
"""
import html
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_schema_drawio as g  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "sample_specs"
OUT = ROOT / "docs" / "sample_specs_schemas.drawio"
TS = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
SHORT = {"Microsoft-Windows-Sysmon/Operational": "Sysmon", "Microsoft-Windows-PowerShell/Operational": "PowerShell"}
SOURCES = [  # (panel key, sample file, schema file for event keys, family of one payload)
    ("defender", "01_microsoft_defender", "01_microsoft_defender",
     lambda p: "AlertInfo / AlertEvidence" if "AlertId" in p else
     {"ProcessCreated": "DeviceProcessEvents", "FileCreated": "DeviceFileEvents"}.get(
         p.get("ActionType"), "DeviceNetworkEvents" if str(p.get("ActionType", "")).startswith("Connection") else p.get("ActionType"))),
    ("entra", "02_microsoft_entra_id", "02_microsoft_entra_id",
     lambda p: "signIn" if "createdDateTime" in p else "directoryAudit"),
    ("cloudtrail", "03_aws_cloudtrail", "03_aws_cloudtrail", lambda p: "CloudTrail record"),
    ("windows", "04_windows_event_logs", "04_windows_event_logs", None),
    ("firewall", "05_network_firewall", "05_firewall", None),
]


def scalar_type(v):
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "timestamp" if TS.match(v) else "ip" if IPV4.match(v) else "string"
    return "null" if v is None else type(v).__name__


def flatten(obj, prefix="", out=None):
    """{dotted.path: value}; lists of objects become path[].child (values from every element)."""
    out = {} if out is None else out
    for k, v in obj.items():
        path = prefix + k
        if isinstance(v, dict):
            out.setdefault(path, []).append({})
            flatten(v, path + ".", out)
        elif isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            out.setdefault(path, []).append([])
            for x in v:
                flatten(x, path + "[].", out)
        else:
            out.setdefault(path, []).append(v)
    return out


def infer(payloads, keys):
    """Rows for one family, from its sample payloads."""
    seen = [flatten(p) for p in payloads]
    order = list(dict.fromkeys(path for s in seen for path in s))
    rows = []
    for path in order:
        values = [v for s in seen for v in s.get(path, [])]
        present = sum(path in s for s in seen)
        kinds = list(dict.fromkeys(
            "object" if isinstance(v, dict) else
            f"array<{'|'.join(dict.fromkeys(scalar_type(x) for x in v)) or 'object'}>" if isinstance(v, list) else
            scalar_type(v) for v in values if v is not None))
        nullable = any(v is None for v in values)
        example = next((v for v in values if v not in (None, {}, []) and not isinstance(v, (dict, list))), None)
        notes = []
        if present < len(seen):
            notes.append(f"in {present}/{len(seen)}")
        if example is not None:
            text = str(example)
            notes.append("e.g. " + (text if len(text) <= 28 else text[:26] + "…"))
        rows.append({"path": path, "type": ("|".join(kinds) or "null") + ("?" if nullable and kinds else ""),
                     "req": "required" if present == len(seen) and not nullable else "optional",
                     "roles": [], "key": path in keys, "note": " · ".join(notes)})
    return rows


def tables_for(key, sample, family_of, keys):
    records = sample["records"]
    payloads = [r["source_payload"] for r in records]
    if key == "windows":
        parsed = [p["parsed_event"] for p in payloads]
        header = infer([{k: v for k, v in p.items() if k != "EventData"} for p in parsed], keys)
        header.insert(0, {"path": "raw_xml", "type": "string", "req": "required", "roles": [], "key": False,
                          "note": "the rendered <Event> XML"})
        out = [("System header", f"{len(parsed)} records · parsed_event.*", header)]
        groups = defaultdict(list)
        for p in parsed:
            groups[f"{SHORT.get(p['Channel'], p['Channel'])} {p['EventID']}"].append(p.get("EventData", {}))
        out += [(f"EventData · {name}", f"{len(ps)} record(s)", infer(ps, keys)) for name, ps in groups.items()]
        return out
    if key == "firewall":
        top = infer([{k: v for k, v in p.items() if k != "parsed_fields"} for p in payloads], keys)
        return [("Record", f"{len(payloads)} records", top),
                ("parsed_fields (CEF decoded)", f"{len(payloads)} records", infer([p["parsed_fields"] for p in payloads], keys))]
    groups = defaultdict(list)
    for p in payloads:
        groups[family_of(p)].append(p)
    return [(name, f"{len(ps)} record(s)", infer(ps, keys)) for name, ps in groups.items()]


def shared_identifiers(by_source):
    """Identifier-looking values that occur in more than one source, and the fields that carry them."""
    where = defaultdict(set)
    for src, pairs in by_source.items():
        for path, v in pairs:
            if not isinstance(v, str) or TS.match(v) or len(v) < 5:
                continue
            norm = v.split("\\")[-1].lower()  # CORP\j.doe and j.doe are the same account
            if re.search(r"[@.\-\d]", norm) and not norm.startswith(("http", "c:", "<")):
                where[norm].add((src, path))
    multi = {v: locs for v, locs in where.items() if len({s for s, _ in locs}) > 1}
    return sorted(multi.items(), key=lambda kv: (-len({s for s, _ in kv[1]}), kv[0]))[:14]


def main():
    d = g.Drawio()
    files = {f: json.loads((SAMPLES / f"{f}.json").read_text(encoding="utf-8")) for _, f, _, _ in SOURCES}
    first = next(iter(files.values()))
    fill, stroke, _ = g.COLORS["common"]

    file_rows = [{"path": k, "type": "array<object>" if k == "records" else g.value_type(v), "req": "required",
                  "roles": [], "key": False, "note": f"e.g. {str(v)[:30]}" if k != "records" else "one object per sample event"}
                 for k, v in first.items()]
    rec = first["records"][0]
    env_rows = [{"path": k, "type": g.value_type(v), "req": "required", "roles": [], "key": k == "source_event_id",
                 "note": {"source_payload": "the vendor event (panels at right)",
                          "evaluation_metadata": "labels (table below)"}.get(k, f"e.g. {v}" if not isinstance(v, dict) else "")}
                for k, v in rec.items()]
    meta = infer([r["evaluation_metadata"] for s in files.values() for r in s["records"]], set())
    w0 = max(g.table_width("Sample file", "", file_rows), g.table_width("x", "", meta), 440)
    y = 0
    for title, sub, rows, colors, dashed in [
            ("Sample file (one per source)", "sample_specs/0N_*.json", file_rows, (fill, stroke), False),
            ("records[] (every record)", "wrapper around one vendor event", env_rows, (fill, stroke), False),
            ("evaluation_metadata (labels)", "kept beside the payload in these samples only", meta, ("#f8cecc", "#b85450"), True)]:
        g.table(d, title, sub, rows, 0, y, w0, *colors, dashed=dashed)
        y += g.START + g.ROW * len(rows) + g.GAP
    legend = ("<b>Legend</b><br>&#128273; event key (from schemas/)<br><b>bold</b> in every record of the family, never null<br>"
              "plain only in some records (in n/m) or sometimes null (?)<br>grey = type inferred from the values<br>"
              "e.g. = one value seen in the samples")
    g.note(d, legend, 0, y, w0, 130)
    y += 130 + g.GAP

    x, values = w0 + 60, {}
    for key, fname, schema, family_of in SOURCES:
        sample = files[fname]
        tables = tables_for(key, sample, family_of, g.key_tokens(g.load(schema)))
        lines = [f"<b>{html.escape(sample['native_format'])}</b>",
                 f"Families: {html.escape(sample['event_families'])}",
                 f"{sample['record_count']} records · sample_specs/{fname}.json"]
        title = sample["source"]
        x += g.panel(d, key, title, lines, tables, x) + 60
        values[key] = [(p, v) for r in sample["records"] for p, vs in flatten(r["source_payload"]).items() for v in vs]

    lines = ["<b>Identifiers shared across sources in the samples</b> (how the example records link up)"]
    for val, locs in shared_identifiers(values):
        fields = " · ".join(f"{s}: {p}" for s, p in sorted(locs))
        lines.append(f"<br><b>{html.escape(val)}</b>: {html.escape(fields)}")
    est = sum(-(-len(re.sub(r'<[^>]+>', '', html.unescape(line))) // 58) for line in lines)
    g.note(d, "".join(lines), 0, y, w0, 30 + est * 17, stroke="#6c8ebf")

    OUT.write_text(d.xml().replace('name="Data source schemas"', 'name="Sample spec schemas"'), encoding="utf-8")
    return d


if __name__ == "__main__":
    out = main()
    print(f"wrote {OUT} ({len(out.cells)} cells, {len(out.boxes)} boxes)")
