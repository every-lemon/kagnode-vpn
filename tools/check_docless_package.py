#!/usr/bin/env python3
"""Install the real package in an isolated chroot with documentation excluded."""

from pathlib import Path
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    args = parser.parse_args()
    package = args.package.resolve(strict=True)
    if os.geteuid() != 0:
        parser.error(
            "Run as root; the package scripts execute only inside the temporary chroot."
        )
    with tempfile.TemporaryDirectory(prefix="kagnode-docless-package-") as temporary:
        root = Path(temporary)

        def copy(source, destination=None):
            source = Path(source)
            target = root / str(destination or source).lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target, follow_symlinks=True)

        python = Path(sys.executable).resolve()
        stdlib = Path(
            subprocess.check_output(
                [
                    str(python),
                    "-c",
                    'import sysconfig;print(sysconfig.get_path("stdlib"))',
                ],
                text=True,
            ).strip()
        )
        shutil.copytree(
            stdlib,
            root / str(stdlib).lstrip("/"),
            ignore=shutil.ignore_patterns(
                "__pycache__",
                "site-packages",
                "dist-packages",
                "test",
                "tests",
                "tkinter",
                "idlelib",
                "ensurepip",
            ),
        )
        copy(python, "/usr/bin/python3")
        copy("/bin/sh", "/bin/sh")
        copy("/usr/bin/install")
        # Copy the interpreter's and extension modules' actual shared-library
        # dependencies. No host filesystem is mounted inside this test root.
        objects = [
            python,
            Path("/bin/sh"),
            Path("/usr/bin/install"),
            *stdlib.rglob("*.so"),
        ]
        dependencies = set()
        for item in objects:
            result = subprocess.run(
                ["ldd", str(item)], capture_output=True, text=True, check=False
            )
            dependencies.update(re.findall(r"(?:=>\s+)?(/[^\s]+)", result.stdout))
        for name in dependencies:
            if Path(name).is_file():
                copy(name)
        (root / "var/lib/dpkg").mkdir(parents=True)
        (root / "var/lib/dpkg/status").touch()
        retained = root / "usr/lib/vpn.before-kagnode-vpn"
        retained.mkdir(parents=True)
        (retained / "retained.txt").write_text("Preserved original application\n")
        journal = root / "var/lib/kagnode-migrations/vpn.json"
        journal.parent.mkdir(parents=True)
        journal.write_text(
            json.dumps(
                {
                    "project": "vpn",
                    "root": "/",
                    "status": "complete",
                    "records": [
                        {
                            "old": "/usr/lib/vpn",
                            "new": "/opt/kagnode/vpn",
                            "backup": "usr/lib/vpn.before-kagnode-vpn",
                            "stage": "complete",
                        }
                    ],
                }
            )
        )
        result = subprocess.run(
            [
                "dpkg",
                "--root=" + str(root),
                "--force-depends",
                "--path-exclude=/usr/share/doc/*",
                "--install",
                str(package),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise RuntimeError(
                "Isolated package installation failed:\n"
                + result.stdout
                + result.stderr
            )
        assert not (root / "usr/share/doc/vpn/migrate-paths.py").exists()
        helper = root / "opt/kagnode/vpn/helpers/migrate-paths.py"
        assert helper.is_file()
        assert (root / "usr/lib/vpn").is_symlink()
        assert (root / "usr/lib/vpn").resolve() == (root / "opt/kagnode/vpn").resolve()
        assert (
            retained / "retained.txt"
        ).read_text() == "Preserved original application\n"
        assert (
            "Status: install ok installed" in (root / "var/lib/dpkg/status").read_text()
        )
        print(
            "PASS real Debian install with documentation excluded, completed migration link repair and retained original."
        )


if __name__ == "__main__":
    main()
