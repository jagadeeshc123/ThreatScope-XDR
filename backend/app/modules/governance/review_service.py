from fastapi import HTTPException


def validate_period(start, end):
    if end < start:
        raise HTTPException(422, "Review period end cannot be earlier than its start")
