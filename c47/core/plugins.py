"""Plugin discovery and instantiation.

Three discovery mechanisms, in increasing order of precedence:

1. **Entry points** -- anything declaring ``c47.lures`` / ``c47.detectors`` /
   ``c47.surfaces`` / ``c47.sinks`` / ``c47.llm``. This is how the built-ins and
   third-party pip packages register.
2. **Plugin paths** -- directories listed in ``[plugins] paths``. Every
   ``*.py`` in them is imported and scanned for ``Plugin`` subclasses. This is
   the fast path for writing a one-off technique without packaging it.
3. **Explicit imports** -- ``[plugins] modules`` for dotted module paths.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import sys
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, TypeVar

from c47.core.spi import Detector, LLMBackend, Lure, Plugin, Sink, Surface

log = logging.getLogger("c47.plugins")

P = TypeVar("P", bound=Plugin)

#: entry-point group -> expected base class
GROUPS: dict[str, type[Plugin]] = {
    "c47.lures": Lure,
    "c47.detectors": Detector,
    "c47.surfaces": Surface,
    "c47.sinks": Sink,
    "c47.llm": LLMBackend,
}

BASES: tuple[type[Plugin], ...] = (Lure, Detector, Surface, Sink, LLMBackend)


class PluginError(RuntimeError):
    pass


@dataclass
class Registry:
    """Name -> class, partitioned by base type."""

    classes: dict[type[Plugin], dict[str, type[Plugin]]] = field(default_factory=dict)
    #: Discovery problems, surfaced by ``c47 plugins`` rather than raised, so a
    #: single broken third-party plugin cannot take the honeypot down.
    errors: list[str] = field(default_factory=list)

    def _bucket(self, base: type[Plugin]) -> dict[str, type[Plugin]]:
        return self.classes.setdefault(base, {})

    def add(self, cls: type[Plugin], *, source: str = "") -> None:
        base = next((b for b in BASES if issubclass(cls, b)), None)
        if base is None:
            return
        if inspect.isabstract(cls) or cls in BASES:
            return
        name = getattr(cls, "name", "") or ""
        if not name:
            self.errors.append(f"{cls.__module__}.{cls.__qualname__} has no `name`; skipped")
            return
        bucket = self._bucket(base)
        if name in bucket and bucket[name] is not cls:
            log.debug("plugin %r from %s overrides %s", name, source, bucket[name].__module__)
        bucket[name] = cls

    def get(self, base: type[P], name: str) -> type[P]:
        bucket = self.classes.get(base, {})
        if name not in bucket:
            known = ", ".join(sorted(bucket)) or "<none>"
            raise PluginError(f"no {base.__name__.lower()} named {name!r}. Known: {known}")
        return bucket[name]  # type: ignore[return-value]

    def names(self, base: type[Plugin]) -> list[str]:
        return sorted(self.classes.get(base, {}))

    def all(self, base: type[P]) -> dict[str, type[P]]:
        return dict(self.classes.get(base, {}))  # type: ignore[arg-type]

    def instantiate(
        self, base: type[P], name: str, config: dict[str, Any] | None = None
    ) -> P:
        cls = self.get(base, name)
        try:
            return cls(config or {})  # type: ignore[return-value]
        except Exception as exc:  # noqa: BLE001
            raise PluginError(f"failed to construct plugin {name!r}: {exc}") from exc


# --------------------------------------------------------------------------


def _discover_entry_points(registry: Registry) -> None:
    for group, base in GROUPS.items():
        try:
            eps = entry_points(group=group)
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            registry.errors.append(f"entry-point group {group}: {exc}")
            continue
        for ep in eps:
            try:
                cls = ep.load()
            except Exception as exc:  # noqa: BLE001
                registry.errors.append(f"{group}:{ep.name} failed to import: {exc}")
                continue
            if not (isinstance(cls, type) and issubclass(cls, base)):
                registry.errors.append(
                    f"{group}:{ep.name} is not a {base.__name__} subclass; skipped"
                )
                continue
            # Entry-point name wins over a mismatched class attribute so the
            # config file and pyproject always agree.
            if getattr(cls, "name", "") != ep.name:
                cls.name = ep.name  # type: ignore[attr-defined]
            registry.add(cls, source=f"{group}:{ep.name}")


def _discover_module(registry: Registry, dotted: str) -> None:
    try:
        mod = importlib.import_module(dotted)
    except Exception as exc:  # noqa: BLE001
        registry.errors.append(f"module {dotted} failed to import: {exc}")
        return
    _scan_module(registry, mod, source=dotted)


def _discover_path(registry: Registry, path: Path) -> None:
    if not path.exists():
        registry.errors.append(f"plugin path {path} does not exist")
        return
    files = sorted(path.rglob("*.py")) if path.is_dir() else [path]
    for f in files:
        if f.name.startswith("_"):
            continue
        mod_name = f"c47_ext_{f.stem}_{abs(hash(str(f))) % 10**8}"
        spec = importlib.util.spec_from_file_location(mod_name, f)
        if spec is None or spec.loader is None:
            registry.errors.append(f"cannot load {f}")
            continue
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception as exc:  # noqa: BLE001
            registry.errors.append(f"{f} failed to import: {exc}")
            continue
        _scan_module(registry, mod, source=str(f))


def _scan_module(registry: Registry, mod: Any, *, source: str) -> None:
    for _, obj in vars(mod).copy().items():
        if isinstance(obj, type) and issubclass(obj, Plugin) and obj not in BASES:
            # Only register classes actually defined here, not imported bases.
            if obj.__module__ == mod.__name__:
                registry.add(obj, source=source)


def build_registry(
    *, paths: list[str] | None = None, modules: list[str] | None = None
) -> Registry:
    """Discover every available plugin."""
    registry = Registry()

    # Register the built-ins by import and scan, so codename_47 works from a
    # bare source checkout with no `pip install -e .` and therefore no entry
    # points. Each built-in package's __init__ imports its own submodules, so
    # importing the package is enough to make them visible in sys.modules.
    for pkg in (
        "c47.lures",
        "c47.detectors",
        "c47.surfaces",
        "c47.sinks",
        "c47.llm",
    ):
        try:
            importlib.import_module(pkg)
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            registry.errors.append(f"builtin package {pkg}: {exc}")
            continue
        for mod_name, mod in list(sys.modules.items()):
            if mod is not None and mod_name.startswith(pkg + "."):
                _scan_module(registry, mod, source=mod_name)

    # Entry points run second so an installed third-party package can override
    # a built-in by claiming its name.
    _discover_entry_points(registry)

    for dotted in modules or []:
        _discover_module(registry, dotted)
    for p in paths or []:
        _discover_path(registry, Path(p).expanduser())

    return registry
