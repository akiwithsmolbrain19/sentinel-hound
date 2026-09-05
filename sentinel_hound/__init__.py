"""Sentinel Hound - local-first log threat detection + SOC triage toolkit (stdlib only)."""
from .parser import parse_auth_log, parse_access_log, normalize_event
from .detections import run_all_detections
from .cases import CaseStore

__all__ = ["parse_auth_log", "parse_access_log", "normalize_event", "run_all_detections", "CaseStore"]
__version__ = "1.0.0"
