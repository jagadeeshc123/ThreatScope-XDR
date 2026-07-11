import hashlib
import json
from pathlib import Path

RULES={item["rule_code"]:item for item in json.loads((Path(__file__).parent/"rules"/"document_rules.json").read_text())}

def triggered(features):
    artifacts=features["attachments"]; links=features["link_features"]
    checks={
      "DOC-001":features["has_javascript"],"DOC-002":features["has_open_action"] or features["has_additional_actions"],"DOC-003":features["has_launch_action"],
      "DOC-004":any(a["executable_like"] for a in artifacts),"DOC-005":any(a["script_like"] or a["archive_like"] or a["office_macro_like"] for a in artifacts),
      "DOC-006":features["has_external_uris"],"DOC-007":links["unsafe_uri"],"DOC-008":features["has_acroform"] or features["has_xfa"] or features["has_submit_form"],
      "DOC-009":features["encryption_limited_analysis"],"DOC-010":features["incremental_update"],"DOC-011":bool(features["metadata_anomalies"]),
      "DOC-012":features["text_features"]["social_engineering_detected"],"DOC-013":features["external_uri_count"]>50 or features["annotation_count"]>100,
      "DOC-014":any(a["double_extension"] for a in artifacts),"DOC-015":features["has_signature"],"DOC-016":features["has_remote_action"] or links["remote_reference"],
      "DOC-017":links["sensitive_url"] or "[REDACTED]" in json.dumps(features["metadata"]),
    }
    return [code for code,value in checks.items() if value]

def build_findings(analysis_id, file_hash, features):
    results=[]
    evidence={"DOC-001":"JavaScript object/action marker detected; script content was not evaluated.","DOC-002":"OpenAction or Additional Actions marker detected.","DOC-003":"Launch action marker detected.","DOC-006":f"{features['external_uri_count']} sanitized external URI indicators detected.","DOC-007":"Unsafe URI scheme identified in static text.","DOC-008":"AcroForm, XFA, or form-action marker detected.","DOC-009":"Encrypted content limited available static inspection.","DOC-010":f"{features['eof_count']} EOF markers and incremental={features['incremental_update']}.","DOC-011":"; ".join(features["metadata_anomalies"]),"DOC-012":"Terms: "+", ".join(features["text_features"]["social_engineering_terms"]),"DOC-013":f"URIs={features['external_uri_count']}; annotations={features['annotation_count']}.","DOC-015":"Signature presence detected — cryptographic validity was not verified.","DOC-016":"Remote-file or GoToR reference marker detected.","DOC-017":"Sensitive key name detected; associated value was redacted."}
    for code in triggered(features):
        rule=RULES[code]
        artifact_matches=[a["filename_sanitized"] for a in features["attachments"] if (code=="DOC-004" and a["executable_like"]) or (code=="DOC-005" and (a["script_like"] or a["archive_like"] or a["office_macro_like"])) or (code=="DOC-014" and a["double_extension"])]
        summary=evidence.get(code,"Embedded artifact metadata: "+", ".join(artifact_matches[:10]))[:500]
        fingerprint=hashlib.sha256(f"{file_hash}|{code}|{summary}".encode()).hexdigest()
        values={k:rule[k] for k in ("rule_code","title","category","severity","confidence","description","technical_impact","remediation","manual_validation_required")}
        values["possible_business_impact"]=rule["business_impact"]
        results.append({**values,"analysis_id":analysis_id,"evidence_summary":summary,"fingerprint":fingerprint,"score":rule["score"]})
    return results
