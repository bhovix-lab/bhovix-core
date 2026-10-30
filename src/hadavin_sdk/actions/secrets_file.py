"""`mounted_file` secrets: one file per secret in a mounted folder (no extra).

Works with anything that mounts secrets as files: a Kubernetes Secret volume, the Secrets Store CSI driver,
External Secrets, Docker/Swarm secrets, systemd credentials. `<dir>/<name>` is read, re-read after `ttl_s` (a
rotated mount is picked up), and one trailing newline is dropped. The path must stay inside the folder
(symlinks are resolved first, so Kubernetes' `..data` links work). On POSIX a file readable by every user is
refused: mount with `defaultMode: 0400` (or 0440 with an `fsGroup`), not Kubernetes' default 0644.
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable
from pathlib import Path

from hadavin_sdk.actions.secrets_cache import CachedSecrets
from hadavin_sdk.config import confined
from hadavin_sdk.errors import ConfigError


class MountedFileProvider(CachedSecrets):
    def __init__(
        self, root: Path, ttl_s: float = 300, clock: Callable[[], float] = time.monotonic
    ) -> None:
        super().__init__(ttl_s, clock)
        self.root = Path(root)

    def _fetch(self, name: str) -> str:
        # ConfigError on `..`, absolute names or links out of the folder.
        path = confined(self.root, name)
        try:
            mode = path.stat().st_mode
            if os.name != "nt" and mode & stat.S_IROTH:
                # Windows has no "other" bit; its folder ACL decides who reads the file.
                raise ConfigError(
                    f"secret {name!r}: the file is readable by every user; mount it 0400 or 0440"
                )
            if not stat.S_ISREG(mode):
                raise ConfigError(f"secret {name!r} is not a regular file")
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise ConfigError(f"secret {name!r} not found in the mounted folder") from None
        return text.removesuffix("\n").removesuffix("\r")


def build(settings, deps) -> MountedFileProvider:
    root = Path(settings.dir)
    if not root.is_dir():
        raise ConfigError(f"secrets mounted_file: {root} is not a folder")
    return MountedFileProvider(root, settings.ttl_s)
