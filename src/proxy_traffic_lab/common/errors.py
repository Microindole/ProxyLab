class LabError(Exception):
    """Base exception for expected laboratory failures."""


class ConfigurationError(LabError):
    """Raised when checked-in or runtime configuration is invalid."""


class CommandError(LabError):
    """Raised when a required external command fails."""




