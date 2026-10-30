"""Errors shared by ``config`` and ``backends``, kept here so neither has to import the other."""


class ConfigError(ValueError):
    """The client config is invalid; the process must not start."""
