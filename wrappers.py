# wrappers.py

from tools.nmap_scan import run_nmap_and_report as run_nmap
from tools.nikto_scan import run_nikto
from tools.dirsearch_scan import run_dirsearch
from typing import Dict


def safe_run_nmap(target: str, flags: str="") -> Dict[str, str]:
    result = run_nmap(target, flags)
    return {
        "scanner": "nmap",
        "success": str(result.get("success", False)),
        "report": result.get("report", ""),
        "target": result.get("target", target),
        "flags": result.get("flags", flags)
    }

def safe_run_nikto(target: str) -> Dict[str, str]:
    result = run_nikto(target)
    return {
        "scanner": "nikto",
        "success": str("error" not in result),
        "report": result.get("report", ""),
        "message": result.get("error", "Scan completed successfully."),
        "target": result.get("target", target),
        "report_content": result.get("report_content", "")
    }


def safe_run_dirsearch(target: str) -> Dict[str, str]:
    result = run_dirsearch(target)
    return {
        "scanner": "dirsearch",
        "success": str(result.get("success", False)),
        "report": str(result.get("report") or ""),  # ensure not None
        "target": str(result.get("target") or target),  # fallback to input target
        "paths_found": str(result.get("paths_found") or "0")
    }