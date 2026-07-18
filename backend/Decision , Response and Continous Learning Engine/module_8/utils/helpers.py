import uuid
from datetime import datetime, timezone

def generate_id(prefix: str = "", seed: str = None) -> str:
    if seed:
        unique_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))
    else:
        unique_id = str(uuid.uuid4())
    return f"{prefix}_{unique_id}" if prefix else unique_id

def current_timestamp() -> datetime:
    return datetime.now(timezone.utc)
