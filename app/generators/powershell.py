"""
Backward-compatibility module for PowerShell telemetry generation.
Under the 5-source architecture, PowerShell telemetry is consolidated into Windows Event Logs.
This module re-exports functions from windows_events.py.
"""
from app.generators.windows_events import (
    generate_powershell_script_block_event,
    generate_powershell_process_event,
    generate_windows_baseline_event as generate_powershell_baseline_event,
    BENIGN_PS_SCRIPTS as BENIGN_SCRIPTS
)

__all__ = [
    "generate_powershell_script_block_event",
    "generate_powershell_process_event",
    "generate_powershell_baseline_event",
    "BENIGN_SCRIPTS"
]
