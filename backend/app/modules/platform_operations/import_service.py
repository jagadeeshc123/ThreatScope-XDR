"""Validation-only import facade; live source-module merge is intentionally absent."""
from .export_service import validate_archive

__all__ = ["validate_archive"]
