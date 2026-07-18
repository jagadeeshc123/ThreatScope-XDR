import email.message
import html
import http.client
import json
import smtplib
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from .security import IntegrationSecurityError, ValidatedDestination, canonical_json, sign_hmac


@dataclass
class AdapterResponse:
    status_code: int
    body: bytes
    duration_ms: int
    external_reference: str | None = None
    external_reference_url: str | None = None
    headers: dict | None = None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, destination: ValidatedDestination, timeout: int):
        super().__init__(destination.hostname, destination.port, timeout=timeout, context=ssl.create_default_context())
        self._destination = destination

    def connect(self):
        last = None
        for address in self._destination.addresses:
            try:
                raw = socket.create_connection((address, self._destination.port), self.timeout)
                self.sock = self._context.wrap_socket(raw, server_hostname=self._destination.hostname)
                return
            except (OSError, ssl.SSLError) as exc:
                last = exc
        raise last or OSError("No validated destination address available")


def bounded_https_send(destination: ValidatedDestination, method: str, body: bytes, headers: dict[str, str], timeout: int, response_limit: int) -> AdapterResponse:
    if method not in {"GET", "POST", "PUT", "PATCH"}:
        raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Unsupported connector HTTP method")
    parsed = urlsplit(destination.url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    started = time.monotonic()
    connection = _PinnedHTTPSConnection(destination, timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read(response_limit + 1)
        if len(content) > response_limit:
            raise IntegrationSecurityError("CONNECTOR_RESPONSE_TOO_LARGE", "Connector response exceeded the configured limit")
        safe_headers = {k.casefold(): v[:300] for k, v in response.getheaders() if k.casefold() in {"retry-after", "content-type", "location"}}
        return AdapterResponse(response.status, content, int((time.monotonic() - started) * 1000), headers=safe_headers)
    except (ssl.SSLCertVerificationError, ssl.SSLError) as exc:
        raise IntegrationSecurityError("CONNECTOR_TLS_FAILED", "TLS certificate validation failed") from exc
    except socket.timeout as exc:
        raise IntegrationSecurityError("CONNECTOR_TIMEOUT", "Connector request timed out") from exc
    except OSError as exc:
        raise IntegrationSecurityError("CONNECTOR_TIMEOUT", "Connector connection failed") from exc
    finally:
        connection.close()


def safe_text(value, limit=4000):
    text = html.escape(str(value), quote=True).replace("http://", "hxxp://").replace("https://", "hxxps://")
    return text[:limit]


def build_http_request(connector_type: str, config: dict, credential: dict, payload: dict, event_id: str, idempotency_key: str):
    timestamp = str(int(time.time()))
    headers = {"Content-Type": "application/json", "X-ThreatScope-Event-ID": event_id, "X-ThreatScope-Timestamp": timestamp, "X-ThreatScope-Schema-Version": "1.0", "Idempotency-Key": idempotency_key}
    operation = "POST"
    external_reference_path = None
    if connector_type == "generic_hmac_webhook_outbound":
        url = config["url"]
        body = canonical_json(payload).encode()
        headers["X-ThreatScope-Signature"] = sign_hmac(str(credential["signing_secret"]), timestamp, body)
    elif connector_type == "slack_incoming_webhook":
        url = credential.get("webhook_url") or config["url"]
        body = canonical_json({"text": "ThreatScope: " + safe_text(payload.get("title") or payload.get("summary") or "security event", 2500)}).encode()
    elif connector_type == "microsoft_teams_webhook":
        url = credential.get("webhook_url") or config["url"]
        body = canonical_json({"type": "message", "summary": "ThreatScope security event", "text": "ThreatScope: " + safe_text(payload.get("summary") or payload.get("title") or "security event", 4000)}).encode()
    elif connector_type == "splunk_hec":
        url = config["url"].rstrip("/") + "/services/collector/event"
        if any(key in payload for key in ("spl", "search", "query", "endpoint", "path", "method")):
            raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Splunk search and arbitrary endpoint controls are prohibited")
        index = str(payload.get("index") or config.get("default_index") or "")
        if index not in set(config.get("index_allowlist", [])):
            raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Splunk index is not allowlisted")
        body = canonical_json({"event": payload, "index": index, "source": config.get("source", "threatscope"), "sourcetype": config.get("sourcetype", "threatscope:integration")}).encode()
        headers["Authorization"] = "Splunk " + str(credential["hec_token"])
        if config.get("acknowledgements_enabled"):headers["X-Splunk-Request-Channel"]=event_id
    elif connector_type == "jira_issue":
        base = config["base_url"].rstrip("/")
        allowed_payload={"action","summary","description","comment","transition_id","external_reference","case_id","payload_profile","severity","title","source_entity_type","source_entity_id","soar_execution_uuid"}
        if set(payload)-allowed_payload:raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Jira payload contains an unapproved field")
        action = payload.get("action", "create")
        fields = {k: payload[k] for k in ("summary", "description") if k in payload}
        if action == "create":
            url = base + "/rest/api/2/issue"
            body = canonical_json({"fields": {**fields, "project": {"key": config["project_key"]}, "issuetype": {"name": config["issue_type"]}}}).encode()
        else:
            issue_key = str(payload.get("external_reference", ""))
            if not issue_key or not all(c.isalnum() or c == "-" for c in issue_key): raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Jira issue key is invalid")
            if action == "comment": url = f"{base}/rest/api/2/issue/{quote(issue_key)}/comment"; body = canonical_json({"body": safe_text(payload.get("comment", ""), 10000)}).encode()
            elif action == "transition":
                transition = str(payload.get("transition_id", ""))
                if transition not in {str(x) for x in config.get("transition_ids", [])}: raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Jira transition is not allowlisted")
                url = f"{base}/rest/api/2/issue/{quote(issue_key)}/transitions"; body = canonical_json({"transition": {"id": transition}}).encode()
            else: url = f"{base}/rest/api/2/issue/{quote(issue_key)}"; body = canonical_json({"fields": fields}).encode(); operation = "PUT"
        headers["Authorization"] = ("Bearer " + str(credential.get("api_token", ""))) if not credential.get("username") else "Basic " + __import__("base64").b64encode(f"{credential['username']}:{credential['api_token']}".encode()).decode()
        external_reference_path = base + "/browse/"
    elif connector_type == "servicenow_incident":
        if config.get("table", "incident") not in {"incident"}: raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "ServiceNow table is not approved")
        allowed_payload={"short_description","description","work_notes","impact","urgency","assignment_group","external_reference","case_id","payload_profile","severity","title","source_entity_type","source_entity_id","soar_execution_uuid"}
        if set(payload)-allowed_payload:raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "ServiceNow payload contains an unapproved field")
        base = config["base_url"].rstrip("/"); sys_id = str(payload.get("external_reference", "")); url = base + "/api/now/table/incident" + (f"/{quote(sys_id)}" if sys_id else "")
        allowed = {"short_description", "description", "work_notes", "impact", "urgency", "assignment_group"}; fields = {k: safe_text(v, 10000) for k, v in payload.items() if k in allowed}
        if "assignment_group" in fields and fields["assignment_group"] not in set(config.get("assignment_groups", [])): raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "ServiceNow assignment group is not allowlisted")
        body = canonical_json(fields).encode(); operation = "PATCH" if sys_id else "POST"; headers["Authorization"] = "Bearer " + str(credential.get("token", ""))
    else:
        raise IntegrationSecurityError("CONNECTOR_TYPE_UNKNOWN", "Connector does not support HTTP delivery")
    return url, operation, body, headers, external_reference_path


def send_smtp(config: dict, credential: dict, payload: dict, transport_factory=None) -> AdapterResponse:
    if config.get("tls_mode") not in {"starttls","implicit_tls"}:raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "SMTP TLS is required")
    if payload.get("attachments"):raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "SMTP attachments are prohibited")
    recipients = list(payload.get("recipients", []))
    maximum = min(int(config.get("maximum_recipients", 20)), 20)
    allowed = {str(x).casefold() for x in config.get("allowed_recipient_domains", [])}
    if not recipients or len(recipients) > maximum or any("@" not in x or x.rsplit("@", 1)[1].casefold() not in allowed for x in recipients):
        raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "SMTP recipients violate the configured allowlist")
    message = email.message.EmailMessage(); message["Subject"] = safe_text(payload.get("subject", "ThreatScope security notification"), 200); message["From"] = config["sender_address"]; message["To"] = ", ".join(recipients); message.set_content(safe_text(payload.get("body", ""), 102400))
    factory = transport_factory or (smtplib.SMTP_SSL if config.get("tls_mode") == "implicit_tls" else smtplib.SMTP);client=None
    started = time.monotonic()
    try:
        client = factory(config["host"], int(config["port"]), timeout=min(int(config.get("timeout", 15)), 60), context=ssl.create_default_context()) if config.get("tls_mode") == "implicit_tls" else factory(config["host"], int(config["port"]), timeout=min(int(config.get("timeout", 15)), 60))
        if config.get("tls_mode") == "starttls": client.starttls(context=ssl.create_default_context())
        if credential.get("username"): client.login(credential["username"], credential["password"])
        client.send_message(message)
        return AdapterResponse(250, b"accepted", int((time.monotonic() - started) * 1000))
    except smtplib.SMTPAuthenticationError as exc:
        raise IntegrationSecurityError("CONNECTOR_AUTHENTICATION_FAILED", "SMTP authentication failed") from exc
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise IntegrationSecurityError("CONNECTOR_TIMEOUT", "SMTP delivery failed temporarily") from exc
    finally:
        if client is not None:
            try:client.quit()
            except (smtplib.SMTPException,OSError):pass
