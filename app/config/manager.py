from __future__ import annotations

import os
from pathlib import Path
from threading import RLock
from typing import Any, Mapping

from .models import Settings
from .sources import env_overrides, load_from_toml


class ConfigManager:
    """Central coordinator for loading and reloading application settings."""

    def __init__(self, *, env_var: str = "CONFIG_FILE", default_file: str = "config.toml") -> None:
        self._env_var = env_var
        self._default_file = default_file
        self._lock = RLock()
        self._settings = self._load()

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def config_path(self) -> Path:
        return self._resolve_config_path()

    def reload(self, *, overrides: Mapping[str, Any] | None = None) -> Settings:
        with self._lock:
            self._settings = self._load(overrides)
            return self._settings

    def replace(self, new_settings: Settings) -> Settings:
        with self._lock:
            self._settings = new_settings
            return self._settings

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return self._settings.model_dump()

    def _resolve_config_path(self) -> Path:
        candidate = os.environ.get(self._env_var, self._default_file)
        return Path(candidate)

    def _load(self, overrides: Mapping[str, Any] | None = None) -> Settings:
        data = load_from_toml(self._resolve_config_path())
        data.update(env_overrides(Settings, os.environ))
        if overrides:
            data.update(overrides)
        return Settings(**data)
