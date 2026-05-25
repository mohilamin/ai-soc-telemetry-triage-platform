"""Endpoint detection helpers."""


def suspicious_process(process_name: str) -> bool:
    """Detect suspicious process."""
    return process_name.lower() in {"powershell.exe", "rundll32.exe", "wmic.exe"}

