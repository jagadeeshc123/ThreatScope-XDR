from fastapi import HTTPException


def bounded(value, name):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise HTTPException(422, f"{name} must be an integer from 1 to 5")
    if number < 1 or number > 5:
        raise HTTPException(422, f"{name} must be between 1 and 5")
    return number


def score(likelihood, impact):
    return min(100, bounded(likelihood, "likelihood") * bounded(impact, "impact") * 4)


def severity(value):
    return "critical" if value >= 70 else "high" if value >= 40 else "medium" if value >= 20 else "low"


def appetite(value, assessed=True):
    if not assessed:
        return "not_assessed"
    return "exceeds_appetite" if value >= 60 else "near_appetite" if value >= 40 else "within_appetite"


def calculate(likelihood, impact, residual_likelihood=None, residual_impact=None, assessed=True):
    likelihood = bounded(likelihood, "likelihood")
    impact = bounded(impact, "impact")
    residual_likelihood = bounded(residual_likelihood if residual_likelihood is not None else likelihood, "residual_likelihood")
    residual_impact = bounded(residual_impact if residual_impact is not None else impact, "residual_impact")
    inherent = score(likelihood, impact)
    residual = score(residual_likelihood, residual_impact)
    return {"likelihood": likelihood, "impact": impact, "inherent_score": inherent, "residual_likelihood": residual_likelihood, "residual_impact": residual_impact, "residual_score": residual, "severity": severity(residual), "appetite_status": appetite(residual, assessed)}
