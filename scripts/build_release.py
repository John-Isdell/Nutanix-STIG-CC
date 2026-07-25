#!/usr/bin/env python3
"""Build deterministic, platform-specific source archives and SHA-256 checksums."""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import io
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

COMMON_FILES = (
    "LICENSE",
    "README.md",
    "RELEASE-NOTES.md",
    "SECURITY.md",
    "CLIENT-GUIDE.md",
    "control_center.py",
    "supervisor.py",
    "supervisor_setup.py",
    "app/requirements.txt",
    "app/server.py",
)
COMMON_TREES = (
    "app/core",
    "app/docs",
    "app/static",
    "supervisor_static",
)
PLATFORMS = {
    "windows": {
        "installer": "Install-Control-Center.cmd",
        "extension": ".zip",
    },
    "macos": {
        "installer": "Install-Control-Center.command",
        "extension": ".zip",
    },
    "linux": {
        "installer": "install.sh",
        "extension": ".tar.gz",
    },
}


class ReleaseBuildError(RuntimeError):
    """Raised when a release archive cannot be built safely."""


def source_version() -> str:
    tree = ast.parse((ROOT / "control_center.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "VERSION" for target in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise ReleaseBuildError("control_center.VERSION could not be found.")


def application_versions() -> set[str]:
    tree = ast.parse((ROOT / "app" / "server.py").read_text(encoding="utf-8"))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and VERSION_PATTERN.fullmatch(node.value)
    }


def release_files(installer: str) -> list[Path]:
    relative_paths = [Path(value) for value in COMMON_FILES]
    relative_paths.append(Path(installer))
    for tree_name in COMMON_TREES:
        tree = ROOT / tree_name
        if not tree.is_dir():
            raise ReleaseBuildError(f"Required release directory is missing: {tree_name}")
        relative_paths.extend(
            path.relative_to(ROOT)
            for path in sorted(tree.rglob("*"))
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        )
    unique = sorted(set(relative_paths), key=lambda path: path.as_posix())
    missing = [path.as_posix() for path in unique if not (ROOT / path).is_file()]
    if missing:
        raise ReleaseBuildError("Required release files are missing: " + ", ".join(missing))
    if any((ROOT / path).is_symlink() for path in unique):
        raise ReleaseBuildError("Release archives may not contain symbolic links.")
    return unique


def file_bytes(relative_path: Path, platform_name: str) -> bytes:
    data = (ROOT / relative_path).read_bytes()
    if platform_name == "windows" and relative_path.suffix.lower() == ".cmd":
        text = data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        return text.replace("\n", "\r\n").encode("utf-8")
    return data


def archive_mode(relative_path: Path) -> int:
    if relative_path.suffix == ".command" or relative_path.name == "install.sh":
        return 0o755
    return 0o644


def archive_name(version: str, platform_name: str) -> str:
    extension = str(PLATFORMS[platform_name]["extension"])
    return f"Nutanix-STIG-Control-Center-{version}-{platform_name}{extension}"


def member_name(version: str, relative_path: Path) -> str:
    prefix = PurePosixPath(f"Nutanix-STIG-Control-Center-{version}")
    return str(prefix / PurePosixPath(relative_path.as_posix()))


def build_zip(
    target: Path,
    version: str,
    platform_name: str,
    relative_paths: list[Path],
) -> None:
    with zipfile.ZipFile(
        target,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for relative_path in relative_paths:
            info = zipfile.ZipInfo(member_name(version, relative_path), FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = archive_mode(relative_path) << 16
            archive.writestr(info, file_bytes(relative_path, platform_name))


def build_tar(
    target: Path,
    version: str,
    platform_name: str,
    relative_paths: list[Path],
) -> None:
    with target.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for relative_path in relative_paths:
                    data = file_bytes(relative_path, platform_name)
                    info = tarfile.TarInfo(member_name(version, relative_path))
                    info.size = len(data)
                    info.mode = archive_mode(relative_path)
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, io.BytesIO(data))


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def validate_member_names(
    version: str,
    platform_name: str,
    names: list[str],
) -> None:
    expected = {
        member_name(version, path)
        for path in release_files(str(PLATFORMS[platform_name]["installer"]))
    }
    actual = set(names)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ReleaseBuildError(
            f"{platform_name} archive inventory mismatch. Missing={missing}; extra={extra}"
        )
    blocked = {".git", ".github", ".runtime", "app/data", "tests"}
    for name in actual:
        relative = PurePosixPath(name).relative_to(
            f"Nutanix-STIG-Control-Center-{version}"
        )
        value = relative.as_posix()
        if any(value == item or value.startswith(item + "/") for item in blocked):
            raise ReleaseBuildError(f"Blocked release path was packaged: {value}")


def validate_archive(path: Path, version: str, platform_name: str) -> None:
    installer = str(PLATFORMS[platform_name]["installer"])
    installer_member = member_name(version, Path(installer))
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            validate_member_names(version, platform_name, archive.namelist())
            mode = archive.getinfo(installer_member).external_attr >> 16
            installer_data = archive.read(installer_member)
    else:
        with tarfile.open(path, mode="r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            validate_member_names(
                version,
                platform_name,
                [member.name for member in members],
            )
            installer_info = archive.getmember(installer_member)
            mode = installer_info.mode
            extracted = archive.extractfile(installer_info)
            if extracted is None:
                raise ReleaseBuildError(f"Could not inspect {installer_member}.")
            installer_data = extracted.read()
    expected_mode = archive_mode(Path(installer))
    if mode & 0o777 != expected_mode:
        raise ReleaseBuildError(
            f"{platform_name} installer mode is {oct(mode)}; expected {oct(expected_mode)}."
        )
    if platform_name == "windows":
        if b"\r\n" not in installer_data or b"\n" in installer_data.replace(b"\r\n", b""):
            raise ReleaseBuildError("Windows installer does not use consistent CRLF endings.")


def build_release(version: str, output_dir: Path) -> list[Path]:
    if not VERSION_PATTERN.fullmatch(version):
        raise ReleaseBuildError("Version must use numeric MAJOR.MINOR.PATCH format.")
    current = source_version()
    if version != current:
        raise ReleaseBuildError(
            f"Requested version {version} does not match control_center.VERSION {current}."
        )
    app_versions = application_versions()
    if app_versions != {version}:
        raise ReleaseBuildError(
            f"Requested version {version} does not match application versions "
            f"{sorted(app_versions)}."
        )
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    expected_output_names = {
        archive_name(version, platform_name) for platform_name in PLATFORMS
    } | {"SHA256SUMS.txt"}
    unexpected = sorted(
        path.name
        for path in output_dir.iterdir()
        if path.name not in expected_output_names or not path.is_file()
    )
    if unexpected:
        raise ReleaseBuildError(
            "Output directory contains unexpected entries: " + ", ".join(unexpected)
        )
    for file_name in expected_output_names:
        target = output_dir / file_name
        if target.exists():
            target.unlink()
    artifacts = []
    for platform_name, definition in PLATFORMS.items():
        target = output_dir / archive_name(version, platform_name)
        relative_paths = release_files(str(definition["installer"]))
        if platform_name == "linux":
            build_tar(target, version, platform_name, relative_paths)
        else:
            build_zip(target, version, platform_name, relative_paths)
        validate_archive(target, version, platform_name)
        artifacts.append(target)
    checksums = output_dir / "SHA256SUMS.txt"
    checksums.write_text(
        "".join(f"{digest(path)}  {path.name}\n" for path in sorted(artifacts)),
        encoding="utf-8",
        newline="\n",
    )
    artifacts.append(checksums)
    return artifacts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build platform-specific Nutanix STIG Control Center archives."
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    try:
        artifacts = build_release(args.version, args.output)
    except (OSError, ReleaseBuildError) as exc:
        parser.error(str(exc))
    for artifact in artifacts:
        print(f"{artifact.name}: {artifact.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
