"""Pack file format + loader (mapping-pack-spec §2/§5, rules M1-M4, M13-M14).

A *pack* is data, not code: it maps framework-neutral engine `finding_type`s to
vendor-neutral compliance *controls*. Loading is **fail-closed** — a malformed
pack raises `PackError` rather than silently dropping a control, because a
security product must never run a scan against a broken policy and report a false
pass. YAML is parsed with `safe_load` only (M4): a pack is untrusted data and must
never be able to execute code via a `!!python/...` tag.
"""

from __future__ import annotations

import importlib.resources as resources
from dataclasses import dataclass

import yaml


class PackError(Exception):
    """A pack is malformed (M3). Raised by `load_pack`; never partially loads."""


@dataclass(frozen=True)
class Control:
    """One control: the `finding_type`s that `breached_by` it (M2, control-centric).

    Fields are tuples, not lists, so a loaded pack is genuinely immutable — a
    `frozen` dataclass still lets a caller mutate a list *inside* it, which would
    break determinism (M12). Tuples close that hole.
    """

    id: str
    title: str
    breached_by: tuple[str, ...]


@dataclass(frozen=True)
class PackRef:
    """Pack identity recorded on results so evidence (F9) cites the exact pack (M13)."""

    id: str
    version: int


@dataclass(frozen=True)
class Pack:
    """A validated pack: metadata + a non-empty, unique-id list of controls (M1)."""

    pack: PackRef
    controls: tuple[Control, ...]


def load_pack(yaml_text: str) -> Pack:
    """Parse + validate a pack YAML string, or raise `PackError` (M1-M4).

    Unknown keys are ignored (forward-compat); every *required* key is enforced.
    """
    try:
        raw = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:  # incl. a rejected !!python tag (M4)
        raise PackError(f"pack is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise PackError("pack must be a YAML mapping")
    if "pack" not in raw:
        raise PackError("pack: missing 'pack' metadata")
    if "controls" not in raw:
        raise PackError("pack: missing 'controls'")

    ref = _parse_ref(raw["pack"])

    raw_controls = raw["controls"]
    if not isinstance(raw_controls, list) or not raw_controls:
        raise PackError("pack.controls must be a non-empty list")

    controls: list[Control] = []
    seen: set[str] = set()
    for item in raw_controls:
        control = _parse_control(item)
        if control.id in seen:
            raise PackError(f"duplicate control id: {control.id}")
        seen.add(control.id)
        controls.append(control)
    return Pack(ref, tuple(controls))


def _parse_ref(meta: object) -> PackRef:
    if not isinstance(meta, dict):
        raise PackError("pack.pack must be a mapping")
    pack_id = meta.get("id")
    version = meta.get("version")
    if not isinstance(pack_id, str) or not pack_id.strip():
        raise PackError("pack.id must be a non-empty string")
    # bool is an int subclass — exclude it so `version: true` is not read as 1.
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise PackError("pack.version must be an integer >= 1")
    return PackRef(pack_id, version)


def _parse_control(item: object) -> Control:
    if not isinstance(item, dict):
        raise PackError("each control must be a mapping")
    cid = item.get("id")
    title = item.get("title")
    breached_by = item.get("breached_by")
    if not isinstance(cid, str) or not cid.strip():
        raise PackError("control.id must be a non-empty string")
    if not isinstance(title, str) or not title.strip():
        raise PackError(f"control {cid}: title must be a non-empty string")
    if not isinstance(breached_by, list) or not breached_by:
        raise PackError(f"control {cid}: breached_by must be a non-empty list")
    if not all(isinstance(t, str) and t for t in breached_by):
        raise PackError(f"control {cid}: breached_by must contain non-empty strings")
    return Control(cid, title, tuple(breached_by))


def load_baseline() -> Pack:
    """Load the shipped `baseline` pack from package data (mapping-pack-spec §6)."""
    text = (
        resources.files("attestable_control_plane")
        .joinpath("packs", "baseline.yaml")
        .read_text(encoding="utf-8")
    )
    return load_pack(text)


__all__ = ["Control", "Pack", "PackRef", "PackError", "load_pack", "load_baseline"]
