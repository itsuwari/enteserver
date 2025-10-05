from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Type

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - fallback for Python <3.11
    import tomli as tomllib  # type: ignore

from pydantic import BaseModel


def load_from_toml(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}

    file_path = Path(path)
    if not file_path.exists():
        return {}

    with file_path.open("rb") as handle:
        data = tomllib.load(handle)

    flattened: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, MutableMapping):
            if key == "s3":
                backends = value.get("backends")
                if backends:
                    flattened["s3_backends"] = backends
                value = {subkey: subval for subkey, subval in value.items() if subkey != "backends"}
            for subkey, subval in value.items():
                flattened[f"{key}_{subkey}"] = subval
        else:
            flattened[key] = value
    return flattened


def env_overrides(model: Type[BaseModel], environ: Mapping[str, str]) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    for field in model.model_fields:
        env_key = field.upper()
        if env_key in environ:
            overrides[field] = environ[env_key]
    return overrides
