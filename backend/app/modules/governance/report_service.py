import html,json
from app import models
from .coverage_service import framework_coverage
from .service import DISCLAIMER,activity,notify_once
from .snapshot_service import metrics,capture

SECTIONS={
"executive_risk":["Executive Summary","Reporting Scope","Current Risk Posture","Inherent and Residual Risk","Risks Exceeding Appetite","Top Risks","Overdue Risks and Treatments","Active Exceptions","Incident and Correlation Context","Framework Coverage Summary","Major Control Gaps","Evidence Readiness","Governance Trends","Recommended Management Actions","Methodology","Limitations","Non-Certification Disclaimer"],
"risk_register":["Register Summary","Scope and Filters","Risk Matrix","Open Risks","High and Critical Risks","Risk Ownership","Treatment Strategies","Treatment Progress","Exceptions","Overdue Reviews","Source Evidence","Control Mappings","Closed Risks","Methodology","Limitations"],
"framework_coverage":["Framework Reference","Framework Version","Scope","Coverage Summary","Supported Controls","Partial Controls","Control Gaps","Not-Assessed Controls","Not-Applicable Controls","Confirmed Mappings","Candidate Mappings","Evidence Summary","Related Risks","Recommended Review Actions","Methodology","Limitations","Non-Certification Disclaimer"],
"evidence_package":["Package Metadata","Scope","Framework Context","Control Context","Risk Context","Evidence Inventory","Evidence Strength","Evidence Sources","Missing Evidence","Review Status","Analyst Notes","Methodology","Limitations","Evidence-Handling Disclaimer"],
"governance_review":["Review Metadata","Reporting Period","Scope","Conclusions","Immutable Snapshot","Risk Posture","Framework Coverage","Limitations","Non-Certification Disclaimer"]}


def generate(db,report_type,framework=None,package=None,review=None,risk=None):
    if report_type not in SECTIONS:raise ValueError("Unsupported governance report type")
    values=metrics(db);context={"metrics":values,"framework":framework.name if framework else None,"version":framework.version if framework else None,"package":package.package_key if package else None,"review":review.review_key if review else None}
    blocks=[]
    for section in SECTIONS[report_type]:
        if "Disclaimer" in section or section=="Limitations":body=DISCLAIMER+" Findings are based only on evidence available within ThreatScope XDR and require governance review."
        elif section=="Framework Version" and framework:body=f"Referenced version: {framework.version}. This label does not assert that it is current or latest."
        else:body=f"Local evidence-derived governance summary. Aggregate context: {json.dumps(context,default=str)}"
        blocks.append(f"<section><h2>{html.escape(section)}</h2><p>{html.escape(body)}</p></section>")
    title={"executive_risk":"Executive Risk Report","risk_register":"Governance Risk Register Report","framework_coverage":f"{framework.name} Framework Coverage Report" if framework else "Framework Coverage Report","evidence_package":f"Evidence Package {package.package_key} Report" if package else "Evidence Package Report","governance_review":"Governance Review Report"}[report_type]
    content=f"<!doctype html><html><head><meta charset='utf-8'><style>@media print{{button{{display:none}}}}body{{font-family:Arial;max-width:1000px;margin:auto;padding:24px}}section{{border-bottom:1px solid #ddd}}</style></head><body><h1>{html.escape(title)}</h1>{''.join(blocks)}</body></html>"
    report=models.GovernanceReport(report_type=report_type,risk_id=risk.id if risk else None,framework_id=framework.id if framework else None,package_id=package.id if package else None,review_id=review.id if review else None,title=title,html_content=content,summary_json=json.dumps({"sections":SECTIONS[report_type],"metrics":values,"disclaimer":DISCLAIMER}));db.add(report);db.flush();capture(db,"report_generation",source_label=f"report:{report.id}");activity(db,"governance_report_generated",f"Generated {report_type} governance report.",report.id);notify_once(db,"Governance Report Generated",title,"success","governance_report",report.id);db.commit();db.refresh(report);return report
