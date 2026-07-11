from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict

class AnalysisRead(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:int; filename_sanitized:str; file_hash:str; file_size:int; mime_type:str; pdf_version:Optional[str]; page_count:Optional[int]; analysis_status:str
    is_encrypted:bool; encryption_limited_analysis:bool; has_javascript:bool; has_open_action:bool; has_additional_actions:bool; has_launch_action:bool; has_acroform:bool; has_xfa:bool; has_embedded_files:bool; has_external_uris:bool
    external_uri_count:int; embedded_file_count:int; annotation_count:int; metadata_json_redacted:Dict[str,Any]; feature_summary_json:Dict[str,Any]; extracted_text_character_count:int
    risk_score:float; classification:str; confidence:str; methodology:str; error_summary:Optional[str]; created_at:datetime; completed_at:Optional[datetime]
    duplicate_existing:bool=False

class AnalysisPage(BaseModel): items:List[AnalysisRead]; total:int; page:int; page_size:int

class FindingRead(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:int; analysis_id:int; rule_code:str; title:str; category:str; severity:str; confidence:str; description:str; evidence_summary:str; technical_impact:str; possible_business_impact:str; remediation:str; manual_validation_required:bool; fingerprint:str; created_at:datetime

class IndicatorRead(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:int; analysis_id:int; indicator_type:str; normalized_value:str; display_value_redacted:str; context:str; severity:str; confidence:str; source_object:Optional[str]; created_at:datetime

class EmbeddedRead(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:int; analysis_id:int; filename_sanitized:str; extension:Optional[str]; declared_mime_type:Optional[str]; file_size:Optional[int]; sha256:Optional[str]; artifact_type:str; executable_like:bool; archive_like:bool; script_like:bool; office_macro_like:bool; risk_label:str; evidence_summary:str; created_at:datetime

class AnalysisDetail(AnalysisRead): findings:List[FindingRead]; indicators:List[IndicatorRead]; embedded_artifacts:List[EmbeddedRead]

class ReportRead(BaseModel): id:int; analysis_id:Optional[int]; title:str; html_content:str; summary_json:Dict[str,Any]; created_at:datetime

class Overview(BaseModel):
    total_analyses:int; analyses_last_24_hours:int; completed_analyses:int; failed_or_limited_analyses:int; suspicious_analyses:int; high_risk_analyses:int; total_findings:int; high_critical_findings:int; documents_with_javascript:int; documents_with_automatic_actions:int; documents_with_embedded_artifacts:int; documents_with_external_links:int; findings_by_severity:Dict[str,int]; analyses_by_classification:Dict[str,int]; recent_analyses:List[AnalysisRead]; top_finding_categories:List[Dict[str,Any]]; recent_activity:List[Dict[str,Any]]
