from app import models
def rows(db,module=None,limit=500):
 out=[]
 def add(m,t,i,k,v,title,evidence,severity="info",confidence="medium",route=None,watch=False):
  if (not module or module==m) and v and len(out)<limit*5:out.append({"source_module":m,"source_record_type":t,"source_record_id":i,"entity_type":k,"value":v,"title":title,"evidence":evidence,"severity":severity,"confidence":confidence,"route":route,"watch":watch})
 for x in db.query(models.Target).limit(limit):add("web_exposure","target",x.id,"domain",x.domain,x.name,x.base_url,"info","high",f"/targets?highlight={x.id}")
 for x in db.query(models.Finding).limit(limit):
  target=db.query(models.Target).filter_by(id=x.target_id).first();add("web_exposure","finding",x.id,"domain",target.domain if target else None,x.title,x.evidence,x.severity,x.confidence,f"/scans?highlight={x.scan_id}&tab=findings")
 for x in db.query(models.ApiAssessment).limit(limit):
  if x.base_url:
   from urllib.parse import urlsplit;add("api_security","assessment",x.id,"domain",urlsplit(x.base_url).hostname,x.name,x.base_url,"info","high",f"/api-security/assessments/{x.id}")
 for x in db.query(models.ApiEndpoint).limit(limit):add("api_security","endpoint",x.id,"api_endpoint",f"{x.method} {x.path}",x.summary or x.path,"Imported endpoint metadata",x.preliminary_risk_level,"medium",f"/api-security/assessments/{x.assessment_id}/endpoints")
 for x in db.query(models.AuthorizationMatrixEntry).limit(limit):
  try:add("api_security","authorization_matrix",x.id,"api_endpoint",f"{x.endpoint.method} {x.endpoint.path}","Authorization matrix expectation",f"Expected access={x.expected_access}; object scope={x.object_scope}; review={x.review_status}","medium","medium",f"/api-security/assessments/{x.assessment_id}/authorization")
  except Exception:continue
 for x in db.query(models.AuthorizationReview).limit(limit):
  try:add("api_security","authorization_review",x.id,"api_endpoint",f"{x.endpoint.method} {x.endpoint.path}",f"Authorization review: {x.review_type}",f"{x.risk_indicator}; decision={x.analyst_decision}",x.severity,x.confidence,f"/api-security/assessments/{x.assessment_id}/authorization-reviews")
  except Exception:continue
 for x in db.query(models.ApiRole).limit(limit):add("api_security","api_role",x.id,"other",f"api-role:{x.assessment_id}:{x.id}","Bounded API role context",f"Role={x.name[:120]}; privilege={x.privilege_level}","info","medium",f"/api-security/assessments/{x.assessment_id}/authorization")
 for x in db.query(models.ApiBusinessFlow).limit(limit):add("api_security","business_flow",x.id,"other",f"business-flow:{x.assessment_id}:{x.id}",x.name,x.description,"medium" if x.risk_score>=40 else "info","medium",f"/api-security/business-flows/{x.id}")
 for x in db.query(models.ApiBusinessFlowStep).limit(limit):
  try:
   if x.endpoint:add("api_security","business_flow_step",x.id,"api_endpoint",f"{x.endpoint.method} {x.endpoint.path}",x.action_name,f"Flow step {x.step_order}; sensitive operation={x.sensitive_operation}","medium" if x.sensitive_operation else "info","medium",f"/api-security/business-flows/{x.flow_id}")
  except Exception:continue
 for x in db.query(models.ApiBusinessFlowRisk).limit(limit):add("api_security","business_flow_risk",x.id,"other",f"business-flow-risk:{x.flow_id}:{x.id}",x.title,x.evidence_summary,x.severity,x.confidence,f"/api-security/business-flows/{x.flow_id}")
 for x in db.query(models.SocEvent).limit(limit):add("soc_monitor","event",x.id,"ip_address",x.source_ip,x.message or "SOC event",x.raw_preview_redacted or x.message or "Observed locally",x.severity,"medium",f"/soc/events/{x.id}")
 for x in db.query(models.SocAlert).limit(limit):add("soc_monitor","alert",x.id,"ip_address",x.source_ip,x.title,x.evidence_summary,x.severity,x.confidence,f"/soc/alerts/{x.id}")
 for x in db.query(models.SocBlocklistEntry).limit(limit):add("soc_monitor","blocklist",x.id,"ip_address" if x.indicator_type=="ip" else x.indicator_type,x.indicator_value,"Local simulated blocklist",x.reason,"medium","high","/soc/blocklist",x.status=="active")
 for x in db.query(models.DocumentIndicator).limit(limit):
  kind={"ip":"ip_address","email":"email_address","file_hash":"file_hash","url":"url"}.get(x.indicator_type,x.indicator_type);add("document_threat","indicator",x.id,kind,x.normalized_value,f"Document {x.indicator_type} indicator",x.context,x.severity,x.confidence,f"/document-threats/analyses/{x.analysis_id}")
 for x in db.query(models.DocumentEmbeddedArtifact).limit(limit):add("document_threat","attachment",x.id,"attachment_hash",x.sha256,x.filename_sanitized,x.evidence_summary,"medium","high",f"/document-threats/analyses/{x.analysis_id}")
 for x in db.query(models.PhishingIndicator).limit(limit):
  kind={"ip":"ip_address","sender_email":"email_address","url":"url"}.get(x.indicator_type,x.indicator_type);add("phishing_defense","indicator",x.id,kind,x.normalized_value,f"Phishing {x.indicator_type} indicator",x.context,x.severity,x.confidence,f"/phishing-defense/analyses/{x.analysis_id}")
 for x in db.query(models.PhishingAttachmentMetadata).limit(limit):add("phishing_defense","attachment",x.id,"attachment_hash",x.sha256,x.filename_sanitized,x.evidence_summary,"medium","high",f"/phishing-defense/analyses/{x.analysis_id}")
 for x in db.query(models.PhishingWatchlistEntry).limit(limit):
  kind={"sender_email":"email_address","url_hash":"url_hash"}.get(x.indicator_type,x.indicator_type);add("phishing_defense","watchlist",x.id,kind,x.normalized_value,"Local phishing watchlist",x.reason,"medium","high","/phishing-defense/watchlist",x.status=="active")
 return out
