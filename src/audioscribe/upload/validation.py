from __future__ import annotations

from pathlib import Path

from .validator import MediaValidation, validate_media


class ValidationError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_staged_media(path: Path, suffix: str) -> MediaValidation:
    """Run the bounded isolated PyAV validator on a closed staged file.

    The file must be closed and flushed before this call; the validator's own
    subprocess isolation (sandbox.py, unchanged) enforces its fixed limits.
    """
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValidationError("invalid_media", "staged media file is missing")
    try:
        with path.open("rb"):
            pass
    except OSError as error:
        raise ValidationError("invalid_media", "staged media file is unreadable") from error
    return validate_media(path, suffix)
