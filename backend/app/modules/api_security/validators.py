from pathlib import Path

from fastapi import HTTPException, UploadFile


MAX_IMPORT_SIZE_BYTES = 1_000_000
OPENAPI_EXTENSIONS = {".json", ".yaml", ".yml"}
POSTMAN_EXTENSIONS = {".json"}


def validate_filename(filename: str | None, allowed_extensions: set[str], label: str) -> str:
    clean_name = Path(filename or "").name
    if not clean_name:
        raise HTTPException(status_code=400, detail=f"{label} filename is required.")
    suffix = Path(clean_name).suffix.lower()
    if suffix not in allowed_extensions:
        allowed = ", ".join(sorted(allowed_extensions))
        raise HTTPException(status_code=400, detail=f"{label} must use one of these extensions: {allowed}.")
    return clean_name


async def read_validated_upload(file: UploadFile, allowed_extensions: set[str], label: str) -> tuple[str, bytes]:
    filename = validate_filename(file.filename, allowed_extensions, label)
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail=f"{label} file is empty.")
    if len(content) > MAX_IMPORT_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"{label} file exceeds the {MAX_IMPORT_SIZE_BYTES // 1_000_000} MB import limit.",
        )
    return filename, content

