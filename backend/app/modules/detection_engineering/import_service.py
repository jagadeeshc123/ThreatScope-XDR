import hashlib
import json
from pathlib import PurePath

import yaml
from yaml.tokens import AliasToken, AnchorToken, TagToken

from .evaluator import validate

MAX_BYTES = 1024 * 1024
MAX_RULES = 50


class ImportError(ValueError):
    pass


def parse(content: str, filename: str):
    raw = content.encode("utf-8")
    if len(raw) > MAX_BYTES: raise ImportError("Rule upload exceeds 1 MiB")
    safe_name = PurePath(filename.replace("\\", "/")).name[:255]
    suffix = safe_name.lower().rsplit(".", 1)[-1] if "." in safe_name else "yaml"
    try:
        if suffix == "json":
            loaded = json.loads(content)
            fmt = "sigma_json"
        else:
            for token in yaml.scan(content):
                if isinstance(token, (AliasToken, AnchorToken)): raise ImportError("YAML aliases and anchors are not supported")
                if isinstance(token, TagToken): raise ImportError("Custom YAML tags are not supported")
            loaded = list(yaml.safe_load_all(content))
            loaded = loaded[0] if len(loaded) == 1 else loaded
            fmt = "sigma_yaml"
    except ImportError: raise
    except (ValueError, yaml.YAMLError, UnicodeError) as exc:
        raise ImportError("Rule file is not valid bounded YAML/JSON") from exc
    if isinstance(loaded, dict): rules=[loaded]
    elif isinstance(loaded, list): rules=loaded
    else: raise ImportError("Rule file must contain an object or list")
    if not rules or len(rules) > MAX_RULES: raise ImportError("Rule file must contain 1-50 rules")
    previews=[]
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            previews.append({"index": index, "valid": False, "errors": ["Rule must be an object"], "warnings": []}); continue
        result=validate(rule)
        supported={"title","id","status","description","references","author","date","modified","tags","logsource","detection","falsepositives","level","selections","condition"}
        warnings=list(result["warnings"])
        unknown=sorted(set(rule)-supported)
        if unknown: warnings.append("Unsupported top-level fields preserved as warnings: " + ", ".join(unknown))
        previews.append({"index": index, "title": str(rule.get("title") or f"Imported rule {index}")[:240], "rule_uuid": str(rule.get("id") or "")[:64] or None,
            "format": fmt, "severity": str(rule.get("level") or "medium").lower(), "content": rule, "content_sha256": hashlib.sha256(json.dumps(rule, sort_keys=True, default=str).encode()).hexdigest(),
            "valid": result["valid"], "errors": result["errors"], "warnings": warnings, "normalized": result["normalized"], "complexity_score": result["complexity_score"]})
    return {"filename": safe_name, "format": fmt, "file_sha256": hashlib.sha256(raw).hexdigest(), "rule_count": len(rules), "previews": previews}
