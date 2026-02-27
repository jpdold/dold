"""CIA risk scoring engine for RMF assessment."""

import pandas as pd
from config.system_types import SYSTEM_TYPES


SCORE_LEVELS = [
    (75, "CRITICAL"),
    (50, "HIGH"),
    (20, "MEDIUM"),
    (0, "LOW"),
]


def _score_to_level(score: float) -> str:
    for threshold, level in SCORE_LEVELS:
        if score >= threshold:
            return level
    return "LOW"


def _stig_component(ckl_df: pd.DataFrame, dimension_weight: float) -> float:
    """Calculate STIG contribution to CIA score for one dimension."""
    if ckl_df is None or ckl_df.empty:
        return 0.0

    open_mask = ckl_df["Status"] == "Open"
    open_df = ckl_df[open_mask]

    cat1 = len(open_df[open_df["CAT"] == "CAT I"])
    cat2 = len(open_df[open_df["CAT"] == "CAT II"])
    cat3 = len(open_df[open_df["CAT"] == "CAT III"])

    raw = (cat1 * 10 + cat2 * 5 + cat3 * 1) * dimension_weight
    return raw


def _cve_component(cve_list: list, impact_key: str) -> float:
    """Calculate CVE contribution to CIA score for one dimension."""
    if not cve_list:
        return 0.0
    total = sum(
        float(cve.get(impact_key, 0) or 0) * 10
        for cve in cve_list
    )
    return total * 0.5


def _emass_component(emass_df: pd.DataFrame, dimension_weight: float) -> float:
    """Calculate eMASS non-compliance contribution to CIA score."""
    if emass_df is None or emass_df.empty:
        return 0.0
    total = len(emass_df)
    if total == 0:
        return 0.0
    non_compliant = len(emass_df[emass_df["Status"] == "NonCompliant"])
    return (non_compliant / total * 100) * 0.3 * dimension_weight


def _kev_bonus(kev_df: pd.DataFrame) -> float:
    """Calculate KEV matched findings bonus."""
    if kev_df is None or kev_df.empty:
        return 0.0
    return len(kev_df) * 8.0


def compute_cia_scores(
    ckl_df: pd.DataFrame,
    cve_list: list,
    emass_df: pd.DataFrame,
    kev_df: pd.DataFrame,
    system_type_key: str,
) -> dict:
    """
    Compute CIA risk scores.

    Parameters
    ----------
    ckl_df : DataFrame from ckl_parser (may be None/empty)
    cve_list : list of CVE dicts from nvd_client (may be empty)
    emass_df : DataFrame from emass_parser (may be None/empty)
    kev_df : DataFrame from cisa_kev matcher (may be None/empty)
    system_type_key : str key into SYSTEM_TYPES dict

    Returns
    -------
    dict: {
        "C": {"score": float, "level": str, "components": {...}},
        "I": {...},
        "A": {...},
        "overall_score": float,
        "overall_level": str,
        "kev_count": int,
        "open_cat1": int,
        "open_cat2": int,
        "open_cat3": int,
        "emass_compliance_pct": float,
    }
    """
    sys_config = SYSTEM_TYPES.get(system_type_key, SYSTEM_TYPES["it_general"])
    criticality_bonus = sys_config["criticality_bonus"]
    kev_count = len(kev_df) if (kev_df is not None and not kev_df.empty) else 0
    kev_bonus_val = _kev_bonus(kev_df)

    # Pre-compute open findings counts
    open_cat1 = open_cat2 = open_cat3 = 0
    if ckl_df is not None and not ckl_df.empty:
        open_df = ckl_df[ckl_df["Status"] == "Open"]
        open_cat1 = len(open_df[open_df["CAT"] == "CAT I"])
        open_cat2 = len(open_df[open_df["CAT"] == "CAT II"])
        open_cat3 = len(open_df[open_df["CAT"] == "CAT III"])

    # eMASS compliance rate
    emass_compliance_pct = 100.0
    if emass_df is not None and not emass_df.empty:
        total = len(emass_df)
        if total > 0:
            compliant = len(emass_df[emass_df["Status"] == "Compliant"])
            emass_compliance_pct = compliant / total * 100

    dimension_configs = [
        ("C", sys_config["C_weight"], "C_impact"),
        ("I", sys_config["I_weight"], "I_impact"),
        ("A", sys_config["A_weight"], "A_impact"),
    ]

    scores = {}
    for dim, weight, impact_key in dimension_configs:
        stig_score = _stig_component(ckl_df, weight)
        cve_score = _cve_component(cve_list, impact_key)
        emass_score = _emass_component(emass_df, weight)
        raw = stig_score + cve_score + emass_score + kev_bonus_val + criticality_bonus
        normalized = min(raw, 100.0)
        scores[dim] = {
            "score": round(normalized, 1),
            "level": _score_to_level(normalized),
            "components": {
                "stig": round(stig_score, 2),
                "cve": round(cve_score, 2),
                "emass": round(emass_score, 2),
                "kev_bonus": round(kev_bonus_val, 2),
                "criticality_bonus": criticality_bonus,
            },
        }

    overall = round((scores["C"]["score"] + scores["I"]["score"] + scores["A"]["score"]) / 3, 1)
    return {
        "C": scores["C"],
        "I": scores["I"],
        "A": scores["A"],
        "overall_score": overall,
        "overall_level": _score_to_level(overall),
        "kev_count": kev_count,
        "open_cat1": open_cat1,
        "open_cat2": open_cat2,
        "open_cat3": open_cat3,
        "emass_compliance_pct": round(emass_compliance_pct, 1),
    }
