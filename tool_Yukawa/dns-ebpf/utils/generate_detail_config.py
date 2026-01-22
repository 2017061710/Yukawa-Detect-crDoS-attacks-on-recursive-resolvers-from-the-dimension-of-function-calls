#!/usr/bin/env python3
"""Generate detail-mode YAML config from hook metadata."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


HOOK_DEFINE_PATTERN = re.compile(r"^#define\s+(HOOK_[A-Za-z0-9_]+)\s+(\d+)")


def load_hook_item(path: Path) -> Dict[str, dict]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_hook_id_map(file_path: Path) -> Dict[str, int]:
    hook_map: Dict[str, int] = {}

    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            m = HOOK_DEFINE_PATTERN.match(line)
            if not m:
                continue
            name, value = m.groups()
            hook_map[name] = int(value)

    if not hook_map:
        raise ValueError(
            f"No hook IDs found in {file_path}. Ensure the file contains HOOK_ defines."
        )
    return hook_map


def _infer_position_from_name(name_without_prefix: str) -> str:
    if name_without_prefix.endswith("_entry"):
        return "entry"
    if name_without_prefix.endswith("_return"):
        return "return"
    return "entry"


def _build_hook_items_index(hook_items: Dict[str, dict]) -> Dict[str, Dict[str, dict]]:
    """Index hook items by function name and position."""

    idx: Dict[str, Dict[str, dict]] = {}
    for item in hook_items.values():
        func_name = item.get("func_name")
        position = item.get("position") or "entry"
        if not func_name:
            continue
        pos_map = idx.setdefault(func_name, {})
        pos_map[position] = item
    return idx


def _strip_position_suffix(program_name: str) -> Tuple[str, bool]:
    for suffix in ("_entry", "_return"):
        if program_name.endswith(suffix):
            return program_name[: -len(suffix)], True
    return program_name, False


def _match_hook_item(
    base_name: str,
    hook_items_by_func: Dict[str, Dict[str, dict]],
    desired_position: str | None,
) -> Tuple[dict | None, str | None]:
    pos_map = hook_items_by_func.get(base_name)
    if not pos_map:
        return None, base_name

    if desired_position and desired_position in pos_map:
        return pos_map[desired_position], None

    # Prefer entry, then return, then any available position.
    fallback = pos_map.get("entry") or pos_map.get("return")
    if fallback:
        return fallback, None
    # If there are other keys, return the first deterministically.
    for pos in sorted(pos_map):
        return pos_map[pos], None

    return None, base_name


def build_program_entries(
    hook_ids: Dict[str, int],
    hook_items_by_func: Dict[str, dict],
    symbol_prefix: str,
    strict: bool,
) -> Tuple[List[dict], List[str]]:
    programs: List[dict] = []
    missing: List[str] = []

    for hook_macro, _hook_id in sorted(hook_ids.items(), key=lambda kv: kv[1]):
        if not hook_macro.startswith("HOOK_"):
            continue
        name = hook_macro[len("HOOK_") :]
        if not name.startswith(symbol_prefix):
            continue
        position = _infer_position_from_name(name)
        stripped_name = name[len(symbol_prefix) :]
        suffix_stripped, had_suffix = _strip_position_suffix(stripped_name)
        base_name = suffix_stripped if suffix_stripped else stripped_name
        if not base_name:
            continue

        desired_position = position if had_suffix else None
        item, missing_key = _match_hook_item(base_name, hook_items_by_func, desired_position)
        if item is None:
            missing.append(missing_key or base_name)
            if strict:
                raise KeyError(
                    f"Cannot find hook item for macro {hook_macro} (derived func: {missing_key})"
                )
            continue

        programs.append(
            {
                "name": name,
                "bin_path": item["file_name"],
                "symbol": item["func_name"],
                "position": position,
            }
        )

    return programs, missing


def generate_programs_yaml(
    hook_header_path: Path,
    programs: Iterable[dict],
    maps_keep: Iterable[str],
    event_decoder: str,
) -> str:
    lines: List[str] = []
    lines.append("programs:")
    for p in programs:
        lines.append(f"  - name: {p['name']}")
        lines.append(f"    bin_path: \"{p['bin_path']}\"")
        lines.append(f"    symbol: \"{p['symbol']}\"")
        lines.append(f"    position: \"{p['position']}\"")
    lines.append("maps:")
    for name in maps_keep:
        lines.append(f"  - name: \"{name}\"")
    lines.append("infos:")
    lines.append(f"  - hook_id: \"{hook_header_path}\"")
    lines.append(f"event_decoder: \"{event_decoder}\"")
    return "\n".join(lines)


def write_yaml_file(output_path: Path, yaml_text: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(yaml_text, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate detail config YAML from hook_ids.h and hook_items.json",
    )
    parser.add_argument(
        "--hook-header",
        required=True,
        type=Path,
        help="Path to hook_ids.h",
    )
    parser.add_argument(
        "--hook-items",
        required=True,
        type=Path,
        help="Path to hook_items.json produced by normal mode",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("config/generated_config.yaml"),
        help="Destination YAML path (default: config/generated_config.yaml)",
    )
    parser.add_argument(
        "--map",
        action="append",
        dest="maps",
        default=None,
        help="Map name to keep (repeatable). Default: hook_event_map",
    )
    parser.add_argument(
        "--symbol-prefix",
        default="uprobe_bind_",
        help="Prefix after HOOK_ within hook_ids.h (e.g. uprobe_bind_)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Raise an error if any hook cannot be resolved",
    )
    parser.add_argument(
        "--event_decoder",
        default="bind_9_16_2",
        help="Event decoder to reference in the generated config",   
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    hook_ids = extract_hook_id_map(args.hook_header)
    hook_items = load_hook_item(args.hook_items)
    hook_items_by_func = _build_hook_items_index(hook_items)

    programs, missing = build_program_entries(
        hook_ids,
        hook_items_by_func,
        symbol_prefix=args.symbol_prefix,
        strict=args.strict,
    )

    maps_keep = args.maps or ["hook_event_map"]
    yaml_text = generate_programs_yaml(args.hook_header, programs, maps_keep, event_decoder=args.event_decoder)
    write_yaml_file(args.output, yaml_text)

    if missing:
        missing_list = ", ".join(sorted(set(missing)))
        print(
            "[warn] missing hook_items for: "
            f"{missing_list}. They were skipped (use --strict to fail)."
        )
    print(f"Generated {args.output}")


if __name__ == "__main__":
    main()
