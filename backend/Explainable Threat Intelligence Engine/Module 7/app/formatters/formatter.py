from datetime import datetime
from typing import List, Union

class ReportFormatter:
    """
    Handles deterministic presentation formatting for lists, datetimes, and paragraphs.
    """

    def format_timestamp(self, ts: Union[datetime, str]) -> str:
        """Formats a timestamp into a standard human-readable ISO string format."""
        if isinstance(ts, datetime):
            return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            return str(ts)

    def format_list_to_bullets(self, items: List[str]) -> List[str]:
        """Ensures list items are formatted with consistent capitalization and spacing."""
        formatted = []
        for item in items:
            item_str = str(item).strip()
            if item_str:
                # Capitalize first letter if not already capitalized
                if len(item_str) > 0:
                    item_str = item_str[0].upper() + item_str[1:]
                # Add trailing period if missing
                if not item_str.endswith((".", "!", "?")):
                    item_str += "."
                formatted.append(item_str)
        return formatted

    def format_score_to_percentage(self, score: float) -> str:
        """Formats risk score to percentage representation (e.g. 85.5%)."""
        return f"{score:.1f}%"

    def format_confidence_to_score(self, score: float) -> str:
        """Formats confidence value (0.0 to 1.0) as decimal or readable label."""
        return f"{score:.2f}"
