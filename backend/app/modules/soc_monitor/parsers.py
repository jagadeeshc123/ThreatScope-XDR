import csv
import io
import json
import re
import shlex
from typing import Any, Dict, List, Tuple


ACCESS_RE = re.compile(r'^(?P<source_ip>\S+) \S+ (?P<username>\S+) \[(?P<timestamp>[^]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[^\"]+)?" (?P<status>\d{3}) (?:\S+)(?: "[^"]*" "(?P<user_agent>[^"]*)")?')
AUTH_RE = re.compile(r'^(?P<timestamp>\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+\S+\s+[^:]+:\s+(?P<message>.*)$')


def parse_jsonl(text: str) -> List[Tuple[Dict[str, Any] | None, str, str | None]]:
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("JSON value must be an object")
            rows.append((value, line, None))
        except (json.JSONDecodeError, ValueError) as exc:
            rows.append((None, line, str(exc)))
    return rows


def parse_csv(text: str) -> List[Tuple[Dict[str, Any] | None, str, str | None]]:
    rows = []
    try:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            return [(None, text[:200], "CSV header is missing")]
        for row in reader:
            rows.append((dict(row), json.dumps(row, default=str), None))
    except csv.Error as exc:
        rows.append((None, text[:200], str(exc)))
    return rows


def parse_access_log(text: str) -> List[Tuple[Dict[str, Any] | None, str, str | None]]:
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = ACCESS_RE.match(line)
        rows.append((match.groupdict() if match else None, line, None if match else "Unsupported access-log line"))
    return rows


def parse_auth_log(text: str) -> List[Tuple[Dict[str, Any] | None, str, str | None]]:
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = AUTH_RE.match(line)
        if not match:
            rows.append((None, line, "Unsupported authentication-log line"))
            continue
        data = match.groupdict()
        message = data["message"]
        ip_match = re.search(r"\b(?:from|rhost=)(\d{1,3}(?:\.\d{1,3}){3})", message)
        user_match = re.search(r"\b(?:for|user=)\s*(?:invalid user\s+)?([A-Za-z0-9_.-]+)", message)
        data.update({"source_ip": ip_match.group(1) if ip_match else None, "username": user_match.group(1) if user_match else None, "event_type": "authentication", "outcome": "failure" if re.search(r"fail|invalid|denied", message, re.I) else "success"})
        rows.append((data, line, None))
    return rows


def parse_key_value(text: str) -> List[Tuple[Dict[str, Any] | None, str, str | None]]:
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            values = {}
            for token in shlex.split(line):
                if "=" in token:
                    key, value = token.split("=", 1)
                    values[key] = value
            if not values:
                raise ValueError("No key=value fields found")
            rows.append((values, line, None))
        except ValueError as exc:
            rows.append((None, line, str(exc)))
    return rows


PARSERS = {"jsonl": parse_jsonl, "csv": parse_csv, "access_log": parse_access_log, "auth_log": parse_auth_log, "key_value": parse_key_value}


def parse_content(parser_type: str, text: str):
    parser = PARSERS.get(parser_type)
    if not parser:
        raise ValueError("Unsupported parser type")
    return parser(text)

