from __future__ import annotations

import hashlib
from typing import Any, Dict

from airon_aip.identity import AgentIdentity


def dataframe_fingerprint(df: Any) -> Dict[str, Any]:
    """Return a best-effort stable fingerprint for a pandas DataFrame."""

    if not hasattr(df, "to_json"):
        raise TypeError("df must look like a pandas DataFrame")
    payload = df.to_json(orient="split", date_format="iso", default_handler=str)
    return {
        "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "rows": int(getattr(df, "shape", (0, 0))[0]),
        "columns": int(getattr(df, "shape", (0, 0))[1]),
    }


def stamp_dataframe(df: Any, identity: AgentIdentity, *, include_fingerprint: bool = True) -> Any:
    if not hasattr(df, "attrs"):
        raise TypeError("df must expose pandas-style attrs")
    metadata: Dict[str, Any] = identity.public_metadata()
    if include_fingerprint:
        metadata["dataframe"] = dataframe_fingerprint(df)
    df.attrs["airon_aip"] = metadata
    return df
