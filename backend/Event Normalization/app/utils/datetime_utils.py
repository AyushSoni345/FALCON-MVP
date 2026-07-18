from datetime import datetime, timezone
import re

def normalize_to_iso8601(ts_value: str | int | float) -> str:
    """
    Normalizes different timestamp formats (epoch milliseconds, epoch seconds, or formatted strings)
    into a standardized ISO-8601 UTC string (YYYY-MM-DDTHH:MM:SSZ).
    """
    if ts_value is None:
        return datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(ts_value, (int, float)) or (isinstance(ts_value, str) and ts_value.replace(".", "", 1).isdigit()):
        val = float(ts_value)
        if val > 99999999999:
            val = val / 1000.0
        try:
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

    ts_str = str(ts_value).strip()
    
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%b %d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if fmt == "%b %d %H:%M:%S":
                dt = dt.replace(year=datetime.utcnow().year)
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    match = re.search(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", ts_str)
    if match:
        try:
            dt = datetime(
                year=int(match.group(1)),
                month=int(match.group(2)),
                day=int(match.group(3)),
                hour=int(match.group(4)),
                minute=int(match.group(5)),
                second=int(match.group(6)),
                tzinfo=timezone.utc
            )
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    return datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
