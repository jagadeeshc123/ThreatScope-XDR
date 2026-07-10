import json
from functools import lru_cache
from pathlib import Path
from typing import Any


RULES_DIR = Path(__file__).parent / "rules"


@lru_cache
def load_rule_file(name: str) -> Any:
    with (RULES_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def owasp_categories() -> list[dict[str, str]]:
    return load_rule_file("owasp_api_top10_2023.json")


def sensitive_fields() -> list[str]:
    return load_rule_file("sensitive_fields.json")


def remediation_catalog() -> dict[str, dict[str, str]]:
    return load_rule_file("remediation_catalog.json")

