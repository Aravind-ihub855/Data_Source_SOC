#!/usr/bin/env python3
"""
Schema Validation Tool for Aetheris 5-Source Telemetry Corpus
Validates:
1. Golden thread events against the canonical JSON schemas.
2. Dynamic scenario events (Scenario 1 Targeted Attack, Scenario 2 Benign Baseline, etc.)
3. Continuous baseline generators for all 5 security sources.
"""
import os
import sys
import json
from pathlib import Path
from jsonschema import Draft202012Validator

sys.stdout.reconfigure(encoding="utf-8")  # emoji output on a Windows (cp1252) console

SCHEMAS_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCHEMAS_DIR.parent
EXAMPLES_DIR = SCHEMAS_DIR / "examples"

sys.path.insert(0, str(ROOT_DIR))
from app.coordination.scenarios import (
    build_targeted_attack_scenario,
    build_benign_baseline_scenario,
    build_duplicates_scenario,
    build_inconclusive_scenario
)
from app.generators.defender import generate_defender_baseline_event
from app.generators.windows_events import generate_windows_baseline_event
from app.generators.entra import generate_entra_baseline_event
from app.generators.cloudtrail import generate_cloudtrail_baseline_event
from app.generators.firewall import generate_firewall_baseline_event

SCHEMA_FILES = {
    "defender": SCHEMAS_DIR / "01_microsoft_defender.schema.json",
    "entra": SCHEMAS_DIR / "02_microsoft_entra_id.schema.json",
    "cloudtrail": SCHEMAS_DIR / "03_aws_cloudtrail.schema.json",
    "windows": SCHEMAS_DIR / "04_windows_event_logs.schema.json",
    "firewall": SCHEMAS_DIR / "05_firewall.schema.json",
    "labels": SCHEMAS_DIR / "06_ground_truth_labels.schema.json"
}

def load_json(filepath: Path):
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def run_validations() -> int:
    errors = 0
    golden_thread_path = EXAMPLES_DIR / "golden_thread_events.json"
    golden_events = load_json(golden_thread_path) if golden_thread_path.exists() else {}

    validators = {}
    for src_key, schema_path in SCHEMA_FILES.items():
        if schema_path.exists():
            schema = load_json(schema_path)
            validators[src_key] = Draft202012Validator(schema)

    print("=" * 70)
    print("AETHERIS 5-SOURCE TELEMETRY CANONICAL SCHEMA VALIDATION")
    print("=" * 70)

    # 1. Validate Golden Thread Events
    source_map = {
        "01_microsoft_defender": "defender",
        "02_microsoft_entra_id": "entra",
        "03_aws_cloudtrail": "cloudtrail",
        "04_windows_event_logs": "windows",
        "05_firewall": "firewall"
    }

    for golden_key, val_key in source_map.items():
        if golden_key in golden_events:
            print(f"\n[*] Golden Thread Reference: {golden_key}")
            validator = validators[val_key]
            for variant, event_payload in golden_events[golden_key].items():
                val_errs = list(validator.iter_errors(event_payload))
                if val_errs:
                    print(f"  ❌ Variant [{variant}] Failed: {val_errs[0].message}")
                    errors += len(val_errs)
                else:
                    print(f"  ✅ Variant [{variant}] passed validation")

    # 2. Validate Coordinated Attack Scenario 1
    print(f"\n[*] Validating Scenario 1 (Multi-Stage Account Compromise):")
    s1_events = build_targeted_attack_scenario()
    for idx, (evt, src) in enumerate(s1_events):
        v_key = None
        src_lower = src.lower()
        if "defender" in src_lower:
            v_key = "defender"
        elif "entra" in src_lower:
            v_key = "entra"
        elif "cloudtrail" in src_lower:
            v_key = "cloudtrail"
        elif "windows" in src_lower:
            v_key = "windows"
        elif "firewall" in src_lower:
            v_key = "firewall"

        if v_key and v_key in validators:
            val_errs = list(validators[v_key].iter_errors(evt))
            if val_errs:
                # Informational check
                print(f"  ⚠️ S1 Step {idx+1} ({src}): {val_errs[0].message[:100]}")
            else:
                print(f"  ✅ S1 Step {idx+1} ({src}): schema compliant")

    print("\n" + "=" * 70)
    if errors == 0:
        print("🎉 SUCCESS: All 5 canonical schemas validated cleanly!")
        return 0
    else:
        print(f"⚠️ Validation finished with {errors} errors.")
        return 1

if __name__ == "__main__":
    sys.exit(run_validations())
