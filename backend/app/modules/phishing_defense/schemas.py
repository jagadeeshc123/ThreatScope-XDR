from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator

class EmailTextInput(BaseModel):
    subject:str=Field("",max_length=500);sender:str=Field("",max_length=500);reply_to:Optional[str]=Field(None,max_length=320);body_text:str=Field("",max_length=100000);body_html:Optional[str]=Field(None,max_length=200000);headers:Optional[str]=Field(None,max_length=50000)
    @field_validator("body_text")
    @classmethod
    def nonempty(cls,v,info): return v
class UrlInput(BaseModel): url:str=Field(...,min_length=1,max_length=4000)
class AnalysisUpdate(BaseModel): analyst_disposition:Optional[str]=None;analyst_notes:Optional[str]=Field(None,max_length=5000)
class WatchlistCreate(BaseModel): indicator_type:str;normalized_value:str=Field(...,max_length=2000);reason:str=Field(...,min_length=1,max_length=1000);source_analysis_id:Optional[int]=None;expires_at:Optional[datetime]=None
class WatchlistUpdate(BaseModel): reason:Optional[str]=Field(None,max_length=1000);status:Optional[str]=None;expires_at:Optional[datetime]=None
class Orm(BaseModel):
    model_config={"from_attributes":True,"protected_namespaces":()}
class FindingRead(Orm): id:int;analysis_id:int;rule_code:str;title:str;category:str;severity:str;confidence:str;description:str;evidence_summary:str;technical_impact:str;possible_business_impact:str;remediation:str;manual_validation_required:bool;fingerprint:str;created_at:datetime
class IndicatorRead(Orm): id:int;analysis_id:int;indicator_type:str;normalized_value:str;display_value_redacted:str;context:str;severity:str;confidence:str;source_location:Optional[str];created_at:datetime
class AttachmentRead(Orm): id:int;analysis_id:int;filename_sanitized:str;extension:Optional[str];declared_mime_type:Optional[str];file_size:Optional[int];sha256:Optional[str];executable_like:bool;script_like:bool;archive_like:bool;macro_capable:bool;double_extension:bool;risk_label:str;evidence_summary:str;created_at:datetime
class AnalysisRead(Orm): id:int;source_type:str;source_hash:str;filename_sanitized:Optional[str];subject_redacted:Optional[str];sender_display_redacted:Optional[str];sender_address_redacted:Optional[str];reply_to_redacted:Optional[str];return_path_redacted:Optional[str];recipient_count:int;url_count:int;attachment_count:int;html_present:bool;authentication_results_present:bool;header_summary_json:dict[str,Any];feature_summary_json:dict[str,Any];bounded_text_character_count:int;model_probability:Optional[float];model_label:Optional[str];heuristic_score:float;final_risk_score:float;classification:str;confidence:str;analyst_disposition:str;analyst_notes:Optional[str];analysis_status:str;methodology:str;error_summary:Optional[str];created_at:datetime;completed_at:Optional[datetime];duplicate_existing:bool=False
class AnalysisDetail(AnalysisRead): findings:list[FindingRead];indicators:list[IndicatorRead];attachments:list[AttachmentRead];reports:list[dict[str,Any]]=[]
class AnalysisPage(BaseModel):items:list[AnalysisRead];total:int;page:int;page_size:int
class WatchlistRead(Orm): id:int;indicator_type:str;normalized_value:str;display_value_redacted:str;reason:str;source_analysis_id:Optional[int];status:str;expires_at:Optional[datetime];created_at:datetime;updated_at:datetime
class ReportRead(BaseModel):id:int;analysis_id:Optional[int];title:str;html_content:str;summary_json:dict[str,Any];created_at:datetime
class Overview(BaseModel): total_analyses:int;analyses_last_24_hours:int;completed_analyses:int;failed_analyses:int;suspicious_analyses:int;high_risk_analyses:int;total_findings:int;high_critical_findings:int;analyses_with_sender_mismatch:int;analyses_with_suspicious_urls:int;analyses_with_risky_attachments:int;active_watchlist_entries:int;analyses_by_classification:dict[str,int];findings_by_severity:dict[str,int];top_finding_categories:list[dict[str,Any]];recent_analyses:list[AnalysisRead];recent_activities:list[dict[str,Any]]
