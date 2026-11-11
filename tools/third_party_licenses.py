"""Write the licenses of the packages bundled into the standalone program.

Run inside the build environment: `uv run python tools/third_party_licenses.py > THIRD_PARTY_LICENSES.txt`.
Walks the runtime requirements of scanfuse (no extras) and prints name, version, license and
the license files shipped in each package's metadata.
"""

import importlib.metadata as md
import re
import sys


def runtime_requirements(name: str) -> list[str]:
    result = []
    for req in md.requires(name) or []:
        if "extra ==" in req:
            continue
        marker = req.split(";", 1)[1] if ";" in req else ""
        if marker and "sys_platform" in marker:
            platform = sys.platform
            if f'"{platform}"' not in marker and f"'{platform}'" not in marker and "!=" not in marker:
                continue
        match = re.match(r"[A-Za-z0-9._-]+", req)
        if match:
            result.append(match.group(0))
    return result


def main() -> None:
    seen: dict[str, md.Distribution] = {}
    todo = runtime_requirements("scanfuse")
    while todo:
        name = todo.pop()
        key = name.lower().replace("_", "-")
        if key in seen:
            continue
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            continue
        seen[key] = dist
        todo.extend(runtime_requirements(name))
    print("Third-party software bundled in the scanfuse standalone program")
    print("=" * 64)
    print()
    print(f"Python {sys.version.split()[0]} (Python Software Foundation License)")
    print("The program is built with PyInstaller; its bootloader is GPL-2.0 with an exception that allows")
    print("distributing the bundled program under any license.")
    print()
    print("fpdf2 is licensed under LGPL-3.0-only. Its source is available at https://pypi.org/project/fpdf2/.")
    print("You can replace it by installing scanfuse from source (pip install scanfuse) with another fpdf2")
    print("version, or by rebuilding this program from the scanfuse source with build.py.")
    print()
    for key in sorted(seen):
        dist = seen[key]
        meta = dist.metadata
        license_name = meta.get("License-Expression") or ""
        if not license_name:
            raw = (meta.get("License") or "").strip()
            classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or []
                           if c.startswith("License ::")]
            license_name = raw if raw and len(raw) <= 80 and "\n" not in raw else ", ".join(classifiers)
        print("-" * 64)
        print(f"{meta['Name']} {dist.version}  License: {license_name or 'see below'}")
        print("-" * 64)
        for file in dist.files or []:
            parts = str(file).replace("\\", "/").split("/")
            if parts[0].endswith(".dist-info") and re.match(r"(?i)(licen[cs]e|copying|notice|authors)", parts[-1]):
                try:
                    print(open(dist.locate_file(file), encoding="utf-8", errors="replace").read().strip())
                    print()
                except OSError:
                    pass
        print()


if __name__ == "__main__":
    main()
