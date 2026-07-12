RANK={"info":0,"low":1,"medium":2,"high":3,"critical":4}
def entity_risk(obs,watch=False):
 modules=len({x.source_module for x in obs});peak=max((RANK.get(x.severity,0) for x in obs),default=0);score=min(100,peak*15+modules*12+min(len(obs),10)*2+(15 if watch else 0));sev="info" if score<20 else "low" if score<40 else "medium" if score<60 else "high" if score<80 else "critical";conf="high" if modules>=3 else "medium" if modules>=2 else "low";return score,sev,conf
def match_risk(obs,watch,rule_score):
 score,_,conf=entity_risk(obs,watch);score=min(100,score+rule_score);sev="info" if score<20 else "low" if score<40 else "medium" if score<60 else "high" if score<80 else "critical";return score,sev,conf
