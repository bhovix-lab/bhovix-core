"""`mounted_file` secrets: one file per secret in a mounted folder (no extra).

Works with anything that mounts secrets as files: a Kubernetes Secret volume, the Secrets Store CSI driver,
External Secrets, Docker/Swarm secrets, systemd credentials. `<dir>/<name>` is read, re-read after `ttl_s` (a
rotated mount is picked up), and one trailing newline is dropped. The path must stay inside the folder
(symlinks are resolved first, so Kubernetes' `..data` links work). On POSIX a file readable by every user is
refused, and so is one writable by its group or others: mount with `defaultMode: 0400` (or 0440 with an `fsGroup`),
not Kubernetes' default 0644. The checks run on the opened file (fstat), so nothing changes between check and read.
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
        # ConfigError on `..`, absolute names or links out of the folder. The result is the real path, so
        # O_NOFOLLOW below refuses a link swapped in after this check.
        path = confined(self.root, name)
        # O_NONBLOCK: a FIFO planted in the folder must not hang the open (S_ISREG below then refuses it).
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            raise ConfigError(f"secret {name!r} not found in the mounted folder") from None
        except OSError as exc:  # e.g. PermissionError (wrong owner or fsGroup), ELOOP (a link)
            raise ConfigError(
                f"secret {name!r}: the mounted file cannot be read ({type(exc).__name__})"
            ) from None
        # Checked on the open file itself, so nothing can change between the check and the read.
        with os.fdopen(fd, "rb") as f:
            mode = os.fstat(f.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise ConfigError(f"secret {name!r} is not a regular file")
            # Windows has no group/other bits; its folder ACL decides who reads or writes the file.
            if os.name != "nt" and mode & (stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
                raise ConfigError(
                    f"secret {name!r}: the file is readable by every user or writable by others; "
                    "mount it 0400 or 0440"
                )
            try:
                text = f.read().decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise ConfigError(
                    f"secret {name!r}: the mounted file cannot be read ({type(exc).__name__})"
                ) from None
        return text.removesuffix("\n").removesuffix("\r")


def build(settings, deps) -> MountedFileProvider:
    root = Path(settings.dir)
    if not root.is_dir():
        raise ConfigError(f"secrets mounted_file: {root} is not a folder")
    return MountedFileProvider(root, settings.ttl_s)
