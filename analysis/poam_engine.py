"""
POA&M analysis engine — completeness, timeliness, effectiveness scoring
and gap analysis per NIST SP 800-37 Rev. 2 §3.6 and NIST SP 800-171 §3.12.4.
"""

import datetime
import pandas as pd


# Required fields per NIST SP 800-37 Rev. 2 §3.6 (text-based checks)
_TEXT_REQUIRED = [
    "Weakness_Name",
    "POC",
    "Resources_Required",
    "Milestone_Description",
    "Mitigation",
]
# Date-based required field
_DATE_REQUIRED = "Scheduled_Completion"

# Statuses that count as "active" (not yet closed)
_ACTIVE_STATUSES = {"ongoing", "not started", "in progress", "open"}
_COMPLETED_STATUS = "completed"
_RISK_ACCEPTED_STATUS = "risk accepted"

# Mitigation text minimum length to count as "non-trivial"
_MIN_MITIGATION_LEN = 20

# Days threshold: "Not Started" items flagged after this many days
_NOT_STARTED_FLAG_DAYS = 30


def _today() -> datetime.date:
    return datetime.date.today()


def _text_filled(value) -> bool:
    """Return True if value is a non-empty, non-NaN string."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return False
    return bool(str(value).strip())


def _date_valid(value) -> bool:
    """Return True if value is a non-null, non-NaT Timestamp/date."""
    if value is None:
        return False
    # pd.isnull handles pd.NaT, float nan, and None
    try:
        if pd.isnull(value):
            return False
    except (TypeError, ValueError):
        pass
    if isinstance(value, (pd.Timestamp, datetime.datetime, datetime.date)):
        return True
    return False


def _to_date(value) -> datetime.date | None:
    """Convert Timestamp/datetime/string to date, or None."""
    if value is None:
        return None
    if isinstance(value, pd.Timestamp):
        if pd.isnull(value):
            return None
        return value.date()
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    return None


def _status_lower(row) -> str:
    return str(row.get("Status", "")).strip().lower()


def _missing_text_fields(row) -> list[str]:
    """Return list of required text field names that are empty for this row."""
    missing = []
    for field in _TEXT_REQUIRED:
        if not _text_filled(row.get(field)):
            missing.append(field)
    return missing


# ──────────────────────────────────────────────────────────────────────────────
# Scoring components
# ──────────────────────────────────────────────────────────────────────────────

def _completeness_score(poam_df: pd.DataFrame) -> tuple[float, list[dict]]:
    """
    Per NIST SP 800-37 Rev. 2 §3.6 — 6 required fields per item.

    Returns (completeness_score 0-100, list of per-item completeness dicts).
    """
    if poam_df.empty:
        return 100.0, []

    per_item = []
    for _, row in poam_df.iterrows():
        missing_text = _missing_text_fields(row)
        date_ok = _date_valid(row.get(_DATE_REQUIRED))
        total_required = len(_TEXT_REQUIRED) + 1  # 6 fields
        filled = (len(_TEXT_REQUIRED) - len(missing_text)) + (1 if date_ok else 0)
        completeness = filled / total_required
        missing_all = missing_text + ([] if date_ok else [_DATE_REQUIRED])
        per_item.append({
            "poam_id": str(row.get("POAM_ID", "")),
            "control_id": str(row.get("Control_ID", "")),
            "completeness_ratio": completeness,
            "filled_count": filled,
            "missing_fields": missing_all,
        })

    score = (sum(i["completeness_ratio"] for i in per_item) / len(per_item)) * 100
    return round(score, 1), per_item


def _timeliness_score(poam_df: pd.DataFrame) -> tuple[float, int, int]:
    """
    Per NIST SP 800-171 §3.12.4 — overdue items.

    Returns (timeliness_score 0-100, overdue_count, not_started_late_count).
    """
    if poam_df.empty:
        return 100.0, 0, 0

    today = _today()
    overdue_count = 0
    not_started_late_count = 0
    active_count = 0

    for _, row in poam_df.iterrows():
        status = _status_lower(row)
        if status == _COMPLETED_STATUS:
            continue  # completed items don't count against timeliness
        active_count += 1

        sched = _to_date(row.get("Scheduled_Completion"))
        if sched is not None and sched < today:
            overdue_count += 1

        if status == "not started":
            date_entered = _to_date(row.get("Date_Entered"))
            if date_entered is not None:
                age_days = (today - date_entered).days
                if age_days > _NOT_STARTED_FLAG_DAYS:
                    not_started_late_count += 1

    if active_count == 0:
        return 100.0, 0, not_started_late_count

    score = (1 - overdue_count / active_count) * 100
    return round(max(score, 0.0), 1), overdue_count, not_started_late_count


def _effectiveness_score(poam_df: pd.DataFrame) -> float:
    """
    Process maturity signals — up to 4 points per item, normalized 0-100.

    Points:
      +1 Status is "Ongoing" or "Completed" (not "Not Started")
      +1 Status is "Completed"
      +1 Has non-trivial Mitigation text (> 20 chars)
      +1 Has a valid Milestone_Completion date
    """
    if poam_df.empty:
        return 100.0

    points_total = 0
    max_points = len(poam_df) * 4

    for _, row in poam_df.iterrows():
        status = _status_lower(row)
        points = 0
        # +1 if not "Not Started"
        if status not in ("not started", ""):
            points += 1
        # +1 if "Completed"
        if status == _COMPLETED_STATUS:
            points += 1
        # +1 if mitigation text is non-trivial
        mitigation = str(row.get("Mitigation", "")).strip()
        if len(mitigation) > _MIN_MITIGATION_LEN:
            points += 1
        # +1 if milestone completion date is valid
        if _date_valid(row.get("Milestone_Completion")):
            points += 1
        points_total += points

    if max_points == 0:
        return 100.0
    return round((points_total / max_points) * 100, 1)


# ──────────────────────────────────────────────────────────────────────────────
# Gap analysis
# ──────────────────────────────────────────────────────────────────────────────

def _gap_analysis(poam_df: pd.DataFrame, completeness_items: list[dict]) -> list[dict]:
    """
    Build per-item shortfall list with issues and recommendations.
    """
    today = _today()
    shortfalls = []

    comp_map = {item["poam_id"]: item for item in completeness_items}

    for _, row in poam_df.iterrows():
        poam_id = str(row.get("POAM_ID", ""))
        control_id = str(row.get("Control_ID", ""))
        weakness = str(row.get("Weakness_Name", ""))
        status = _status_lower(row)
        issues = []
        recommendations = []

        # --- Completeness check ---
        comp_item = comp_map.get(poam_id, {})
        missing = comp_item.get("missing_fields", [])
        if comp_item.get("filled_count", 6) < 4:
            field_list = ", ".join(missing) if missing else "unknown"
            issues.append(f"Missing required fields: {field_list}")
            recommendations.append(
                "Populate all required POA&M fields per NIST SP 800-37 Rev. 2 §3.6"
            )

        # --- Timeliness checks ---
        sched = _to_date(row.get("Scheduled_Completion"))
        if sched is not None and sched < today and status != _COMPLETED_STATUS:
            issues.append(
                f"Scheduled completion {sched.isoformat()} is past due"
            )
            recommendations.append(
                "Update milestone or request AO-approved extension within 30 days"
            )

        # --- Not Started + age ---
        if status == "not started":
            date_entered = _to_date(row.get("Date_Entered"))
            if date_entered is not None:
                age_days = (today - date_entered).days
                if age_days > _NOT_STARTED_FLAG_DAYS:
                    issues.append(
                        f"POA&M has not been initiated {age_days} days after entry"
                    )
                    recommendations.append(
                        "Assign owner and initiate remediation immediately"
                    )

        # --- Risk Accepted without justification ---
        if status == _RISK_ACCEPTED_STATUS:
            mitigation = str(row.get("Mitigation", "")).strip()
            if not mitigation:
                issues.append("Risk Accepted without documented justification")
                recommendations.append(
                    "Document risk acceptance rationale and obtain AO sign-off"
                )

        # --- Thin mitigation ---
        mitigation = str(row.get("Mitigation", "")).strip()
        if 0 < len(mitigation) < _MIN_MITIGATION_LEN:
            issues.append("Mitigation plan is insufficient")
            recommendations.append(
                "Document specific technical steps and verification criteria"
            )
        elif not mitigation and status not in (_COMPLETED_STATUS,):
            # Completely missing mitigation (already caught by completeness if < 4 filled,
            # but flag explicitly for items that are otherwise mostly complete)
            if comp_item.get("filled_count", 6) >= 4:
                issues.append("Mitigation plan is insufficient")
                recommendations.append(
                    "Document specific technical steps and verification criteria"
                )

        # --- No milestone dates ---
        if not _date_valid(row.get("Milestone_Completion")):
            if not _text_filled(row.get("Milestone_Description")):
                issues.append("No milestone schedule defined")
                recommendations.append(
                    "Add milestone dates per NIST SP 800-37 Rev. 2 requirements"
                )

        if issues:
            shortfalls.append({
                "poam_id": poam_id,
                "control_id": control_id,
                "weakness_name": weakness,
                "status": str(row.get("Status", "")),
                "issues": issues,
                "recommendations": recommendations,
            })

    return shortfalls


# ──────────────────────────────────────────────────────────────────────────────
# Risk modifier
# ──────────────────────────────────────────────────────────────────────────────

def poam_risk_modifier(health_score: float) -> int:
    """
    Map POA&M health score to a risk score modifier.

    Returns
    -------
    int : modifier applied to each CIA score (positive = more risk)
    """
    if health_score >= 80:
        return -5   # Good POA&M practice (slight credit)
    if health_score >= 60:
        return 0    # Neutral
    if health_score >= 40:
        return 10   # Deficient — risk elevated
    return 20       # Severely deficient — significant escalation


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────

def analyze_poam(poam_df: pd.DataFrame, emass_df: pd.DataFrame = None) -> dict:
    """
    Analyze POA&M completeness, timeliness, and effectiveness.

    Parameters
    ----------
    poam_df : DataFrame from parse_poam()
    emass_df : optional eMASS DataFrame (reserved for future cross-referencing)

    Returns
    -------
    dict with keys:
        completeness_score, timeliness_score, effectiveness_score,
        poam_health_score, risk_modifier, total_items, overdue_count,
        not_started_count, completed_count, shortfalls, items_df
    """
    if poam_df is None or poam_df.empty:
        return {
            "completeness_score": 100.0,
            "timeliness_score": 100.0,
            "effectiveness_score": 100.0,
            "poam_health_score": 100.0,
            "risk_modifier": 0,
            "total_items": 0,
            "overdue_count": 0,
            "not_started_count": 0,
            "completed_count": 0,
            "shortfalls": [],
            "items_df": pd.DataFrame(),
        }

    today = _today()

    completeness_score, completeness_items = _completeness_score(poam_df)
    timeliness_score, overdue_count, _ = _timeliness_score(poam_df)
    effectiveness_score = _effectiveness_score(poam_df)

    poam_health_score = round(
        completeness_score * 0.40
        + timeliness_score * 0.35
        + effectiveness_score * 0.25,
        1,
    )
    modifier = poam_risk_modifier(poam_health_score)

    # Aggregate counts
    total_items = len(poam_df)
    status_lower_series = poam_df["Status"].str.strip().str.lower()
    not_started_count = int((status_lower_series == "not started").sum())
    completed_count = int((status_lower_series == "completed").sum())

    shortfalls = _gap_analysis(poam_df, completeness_items)

    # Build enriched per-item DataFrame
    items_rows = []
    comp_map = {item["poam_id"]: item for item in completeness_items}
    for _, row in poam_df.iterrows():
        poam_id = str(row.get("POAM_ID", ""))
        comp = comp_map.get(poam_id, {})
        status = _status_lower(row)
        sched = _to_date(row.get("Scheduled_Completion"))
        overdue = (
            sched is not None
            and sched < today
            and status != _COMPLETED_STATUS
        )
        items_rows.append({
            "POAM_ID": poam_id,
            "Control_ID": str(row.get("Control_ID", "")),
            "Weakness_Name": str(row.get("Weakness_Name", "")),
            "Status": str(row.get("Status", "")),
            "Severity": str(row.get("Severity", "")),
            "Scheduled_Completion": row.get("Scheduled_Completion"),
            "POC": str(row.get("POC", "")),
            "Mitigation": str(row.get("Mitigation", "")),
            "Completeness_Pct": round(comp.get("completeness_ratio", 1.0) * 100, 0),
            "Overdue": overdue,
        })

    items_df = pd.DataFrame(items_rows)

    return {
        "completeness_score": completeness_score,
        "timeliness_score": timeliness_score,
        "effectiveness_score": effectiveness_score,
        "poam_health_score": poam_health_score,
        "risk_modifier": modifier,
        "total_items": total_items,
        "overdue_count": overdue_count,
        "not_started_count": not_started_count,
        "completed_count": completed_count,
        "shortfalls": shortfalls,
        "items_df": items_df,
    }
