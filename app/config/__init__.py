from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Mapping

from .manager import ConfigManager
from .models import Settings

__all__ = [
    "Settings",
    "settings",
    "get_settings",
    "reload_settings",
    "config_path",
    "as_dict",
    "override",
]

_manager = ConfigManager()
settings: Settings = _manager.settings


def get_settings() -> Settings:
    return settings


def reload_settings(*, overrides: Mapping[str, Any] | None = None) -> Settings:
    global settings
    settings = _manager.reload(overrides=overrides)
    return settings


def config_path() -> Path:
    return _manager.config_path


def as_dict() -> dict[str, Any]:
    return _manager.as_dict()


@contextmanager
def override(**values: Any) -> Generator[Settings, None, None]:
    global settings
    previous = _manager.settings
    try:
        settings = _manager.reload(overrides=values)
        yield settings
    finally:
        settings = _manager.replace(previous)
