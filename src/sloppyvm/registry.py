"""Dynamic discovery and registry of SloppyVM implementation modules.

Searches for files matching the pattern 'v*.py' in the implementations/
subdirectory, imports them, and validates they have the required
execute() function.
"""

import importlib
import pathlib
import re
import sys
from types import ModuleType


def extract_version_from_filename(filename: str) -> int | None:
    """Extract version number from v<N>.py filename."""
    match = re.match(r'v(\d+)\.py', filename)
    return int(match.group(1)) if match else None


def is_valid_implementation(module: ModuleType) -> bool:
    """Validate module has callable execute function."""
    return hasattr(module, 'execute') and callable(module.execute)


def discover_implementations() -> dict[str, tuple[ModuleType, int]]:
    """
    Dynamically discover all SloppyVM implementation modules.

    Searches for files matching the pattern 'v*.py' in the implementations/
    subdirectory, imports them, and validates they have the required
    execute() function.

    Returns:
        Dictionary mapping version identifiers (e.g., 'v1', 'v2') to tuples
        of (module, version_number). Sorted by version number ascending.

    Raises:
        RuntimeError: If no valid implementations are found
    """
    implementations: dict[str, tuple[ModuleType, int]] = {}
    script_dir = pathlib.Path(__file__).parent.resolve()
    impl_dir = script_dir / 'implementations'

    # Add implementations directory to module search path
    sys.path.insert(0, str(impl_dir))

    for file_path in impl_dir.glob('v*.py'):
        version_num = extract_version_from_filename(file_path.name)
        if version_num is None:
            continue

        module_name = file_path.stem
        version_key = f'v{version_num}'

        try:
            module = importlib.import_module(module_name)
            if is_valid_implementation(module):
                implementations[version_key] = (module, version_num)
        except Exception as e:
            print(f"Warning: Failed to import {module_name}: {e} - skipping", file=sys.stderr)

    if not implementations:
        raise RuntimeError("No valid SloppyVM implementations found")

    return dict(sorted(implementations.items(), key=lambda x: x[1][1]))


_IMPLEMENTATION_REGISTRY = discover_implementations()


def get_available_versions() -> list[str]:
    """Return sorted list of available implementation version identifiers."""
    return list(_IMPLEMENTATION_REGISTRY.keys())


def get_implementation(version: str) -> ModuleType:
    """
    Get the implementation module for a given version.

    Args:
        version: Version identifier (e.g., 'v1', 'v2')

    Returns:
        The implementation module

    Raises:
        ValueError: If version is not found
    """
    if version in _IMPLEMENTATION_REGISTRY:
        return _IMPLEMENTATION_REGISTRY[version][0]
    available = ', '.join(get_available_versions())
    raise ValueError(f"Unknown implementation: {version}. Available: {available}")
