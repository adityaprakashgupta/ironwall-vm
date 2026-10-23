#!/usr/bin/env python3
"""
Build deterministic wheels for the LLM MicroVM guest.

The LLM guest image has no package index and no network, so every Python
dependency must be staged at image-build time.  This script repackages the
host's installed llama-cpp-python (and its runtime dependencies) into plain,
deterministic wheels that `microvm/build_immutable_images.sh --llama-wheel-dir`
can consume:

    scripts/build_wheels.py --wheel-dir microvm/wheels

The main llama-cpp-python wheel is built from the host's installed package
(compiled .so files are specific to the host Python version / architecture,
so they must come from the host that builds the images).  Dependency wheels
(typing_extensions, diskcache, jinja2, markupsafe) are discovered
automatically from the host environment.

Determinism
-----------
Every zip entry in each wheel is stamped with a fixed timestamp
(SOURCE_DATE_EPOCH, default 0 = 1980-01-01) so that rebuilding from the same
host environment produces byte-identical wheels.  This keeps image digests
stable across rebuilds of the same source tree.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import sys
import zipfile
from datetime import datetime, timezone

#: Fixed timestamp stamped on every wheel entry for reproducibility.
#: 1980-01-01 00:00:00 UTC is the earliest representable MS-DOS date time.
DEFAULT_EPOCH = 0

#: Distribution name → import package name overrides.  Some distributions
#: install under a different import name than their distribution name
#: (e.g. ``llama_cpp_python`` dist provides the ``llama_cpp`` package).
DIST_TO_IMPORT: dict[str, list[str]] = {
    "llama_cpp_python": ["llama_cpp"],
    "llama-cpp-python": ["llama_cpp"],
}

#: Runtime Python dependencies required by llama-cpp-python inside the guest.
#: Discovered on the host and repackaged as sibling wheels so the image build
#: picks them up automatically alongside the main llama wheel.
DEPENDENCY_PACKAGES = ["typing_extensions", "diskcache", "jinja2", "markupsafe"]


def fixed_epoch() -> int:
    """Return SOURCE_DATE_EPOCH if set, else the fixed default."""
    return int(os.environ.get("SOURCE_DATE_EPOCH", DEFAULT_EPOCH))


def epoch_to_dos(epoch: int) -> tuple[int, int, int, int, int, int]:
    """Convert a unix epoch to a 6-tuple usable as zipfile.ZipInfo.date_time.

    Zip timestamps only have 2-second resolution and cannot represent dates
    before 1980-01-01, so clamp anything earlier to that floor.
    """
    if epoch <= DEFAULT_EPOCH:
        return (1980, 1, 1, 0, 0, 0)
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


def write_deterministic_wheel(src_paths: list[str], out_path: str, epoch: int) -> None:
    """Package `src_paths` (files or directories) into `out_path` with fixed timestamps.

    Archive paths are relative to the common parent of all sources, so a
    directory package like `llama_cpp/` archives as `llama_cpp/...` and a
    single-file module like `typing_extensions.py` archives as just
    `typing_extensions.py`.  All entries are stamped with `epoch` so the
    output is byte-identical across runs.
    """
    date_time = epoch_to_dos(epoch)
    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    if os.path.exists(out_path):
        os.remove(out_path)

    # Common parent directory used as the archive root.
    abs_paths = [os.path.abspath(p) for p in src_paths]
    src_root = os.path.commonpath(abs_paths)

    entries: list[tuple[str, str]] = []  # (full_path, arc_name)
    for src_path in abs_paths:
        if os.path.isdir(src_path):
            for root, _dirs, files in os.walk(src_path):
                for name in sorted(files):
                    full = os.path.join(root, name)
                    arc = os.path.relpath(full, src_root).replace(os.sep, "/")
                    entries.append((full, arc))
        else:
            entries.append((src_path, os.path.relpath(src_path, src_root).replace(os.sep, "/")))

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for full, arc in sorted(entries, key=lambda e: e[1]):
            info = zipfile.ZipInfo(arc, date_time=date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            with open(full, "rb") as fh:
                zf.writestr(info, fh.read())

    print(f"  {os.path.basename(out_path)}  ({os.path.getsize(out_path):,} bytes)")


def discover_package(package_name: str) -> tuple[str, str | None]:
    """Locate a host-installed package and its .dist-info directory.

    Returns (package_path_or_file, dist_info_path_or_None).  The package may be
    a single .py module or a directory package.  The distribution name
    (e.g. ``llama_cpp_python``) may differ from the import package name
    (e.g. ``llama_cpp``), so we read ``top_level.txt`` from the dist-info to
    find the actual importable name.
    """
    dist = importlib.metadata.distribution(package_name)
    if dist is None:
        raise SystemExit(f"package {package_name!r} is not installed on the host")

    base = dist.locate_file("")

    # Read the importable top-level name(s) from top_level.txt.  The
    # distribution name can differ from the import package name
    # (e.g. llama_cpp_python dist installs the llama_cpp package).
    top_level: list[str] = []
    try:
        tl = dist.read_text("top_level.txt")
        if tl:
            top_level = [line.strip() for line in tl.splitlines() if line.strip()]
    except Exception:
        pass

    if not top_level:
        # Use explicit overrides first, then fall back to the distribution name.
        top_level = DIST_TO_IMPORT.get(
            package_name, [package_name.replace("-", "_")]
        )

    pkg_path: str | None = None
    for name in top_level:
        candidate = os.path.join(base, name)
        if os.path.isdir(candidate):
            pkg_path = candidate
            break
        single = os.path.join(base, name + ".py")
        if os.path.exists(single):
            pkg_path = single
            break

    if pkg_path is None:
        raise SystemExit(
            f"could not locate importable package(s) {top_level} for "
            f"{package_name!r} under {base}"
        )

    # Find the .dist-info directory on disk.  dist.metadata['Name'] may use
    # different casing than the on-disk directory (e.g. "Jinja2" vs
    # "jinja2-3.1.6.dist-info"), so scan case-insensitively.
    version = dist.version
    dist_info: str | None = None
    if base and os.path.isdir(base):
        for entry in os.listdir(base):
            if entry.lower().endswith(f"-{version}.dist-info".lower()):
                candidate = os.path.join(base, entry)
                if os.path.isdir(candidate):
                    dist_info = candidate
                    break

    return pkg_path, dist_info


def build_llama_wheel(out_dir: str, epoch: int) -> str:
    """Build the llama-cpp-python wheel from the host's installed package.

    The compiled shared libraries (.so files) inside llama_cpp/lib/ are
    specific to the host Python version and architecture, so they must be
    packaged from the host that builds the images.  The wheel filename uses
    the linux_x86_64 platform tag because it contains compiled extensions.
    """
    pkg_path, dist_info = discover_package("llama_cpp_python")
    dist = importlib.metadata.distribution("llama_cpp_python")
    version = dist.version
    out_name = f"llama_cpp_python-{version}-py3-none-linux_x86_64.whl"
    out_path = os.path.join(out_dir, out_name)
    print(f"  building main wheel {out_name} ...")
    sources = [pkg_path]
    if dist_info:
        sources.append(dist_info)
    write_deterministic_wheel(sources, out_path, epoch)
    return out_path


def build_dependency_wheels(out_dir: str, epoch: int) -> list[str]:
    """Build deterministic wheels for every runtime dependency."""
    built: list[str] = []
    for pkg in DEPENDENCY_PACKAGES:
        try:
            pkg_path, dist_info = discover_package(pkg)
        except SystemExit as exc:
            print(f"  warn: {exc}; skipping")
            continue
        dist = importlib.metadata.distribution(pkg)
        name = dist.metadata["Name"].replace("-", "_")
        version = dist.version
        # Pure-python deps use the py3-none-any tag.
        out_name = f"{name}-{version}-py3-none-any.whl"
        out_path = os.path.join(out_dir, out_name)
        print(f"  building dependency wheel {out_name} ...")
        sources = [pkg_path]
        if dist_info:
            sources.append(dist_info)
        write_deterministic_wheel(sources, out_path, epoch)
        built.append(out_path)
    return built


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build deterministic wheels for the Bayora LLM MicroVM guest."
    )
    parser.add_argument(
        "--wheel-dir",
        default="microvm/wheels",
        help="Output directory for all wheels (default: microvm/wheels). "
        "This directory is passed to build_immutable_images.sh via "
        "--llama-wheel-dir.",
    )
    parser.add_argument(
        "--no-deps",
        action="store_true",
        help="Only build the main llama wheel; do not rebuild dependency wheels.",
    )
    args = parser.parse_args()

    epoch = fixed_epoch()
    wheel_dir = os.path.abspath(args.wheel_dir)
    os.makedirs(wheel_dir, exist_ok=True)

    # Build the main llama-cpp-python wheel from the host's installed package.
    build_llama_wheel(wheel_dir, epoch)

    # Build dependency wheels.
    if not args.no_deps:
        build_dependency_wheels(wheel_dir, epoch)

    print(f"\nAll wheels staged in {wheel_dir}")
    for f in sorted(os.listdir(wheel_dir)):
        print(f"  {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
