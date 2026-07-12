from .web_exposure_adapter import candidates as web_candidates
from .api_security_adapter import candidates as api_candidates
from .soc_adapter import candidates as soc_candidates
from .document_threat_adapter import candidates as document_candidates
from .phishing_adapter import candidates as phishing_candidates
from .correlation_case_adapter import candidates as correlation_candidates

ADAPTERS = {
    "web_exposure": web_candidates,
    "api_security": api_candidates,
    "soc_monitor": soc_candidates,
    "document_threat": document_candidates,
    "phishing_defense": phishing_candidates,
    "unified_correlation": correlation_candidates,
}
