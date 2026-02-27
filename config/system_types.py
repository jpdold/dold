"""System type definitions with CIA weighting factors for RMF assessment."""

SYSTEM_TYPES = {
    "sis_type_i": {
        "label": "SIS Type I",
        "desc": "Safety Instrumented System Type I — highest safety integrity level, direct life/safety impact",
        "C_weight": 1.5,
        "I_weight": 1.8,
        "A_weight": 2.0,
        "criticality_bonus": 20,
    },
    "sis_type_ii": {
        "label": "SIS Type II",
        "desc": "Safety Instrumented System Type II — high safety integrity, significant operational impact",
        "C_weight": 1.4,
        "I_weight": 1.6,
        "A_weight": 1.8,
        "criticality_bonus": 15,
    },
    "sis_type_iii": {
        "label": "SIS Type III",
        "desc": "Safety Instrumented System Type III — moderate safety integrity level",
        "C_weight": 1.2,
        "I_weight": 1.4,
        "A_weight": 1.5,
        "criticality_bonus": 10,
    },
    "crn": {
        "label": "CRN (Critical Resources Network)",
        "desc": "Critical Resources Network — supports critical infrastructure and resource distribution",
        "C_weight": 1.6,
        "I_weight": 1.5,
        "A_weight": 1.7,
        "criticality_bonus": 18,
    },
    "it_general": {
        "label": "IT System (General)",
        "desc": "General-purpose IT system with standard security requirements",
        "C_weight": 1.0,
        "I_weight": 1.0,
        "A_weight": 1.0,
        "criticality_bonus": 0,
    },
    "ics_scada": {
        "label": "ICS/SCADA",
        "desc": "Industrial Control System / Supervisory Control and Data Acquisition — operational technology",
        "C_weight": 1.3,
        "I_weight": 1.8,
        "A_weight": 2.0,
        "criticality_bonus": 18,
    },
    "dod_mission_critical": {
        "label": "DoD Mission Critical",
        "desc": "Department of Defense mission-critical system — direct warfighting or national security impact",
        "C_weight": 2.0,
        "I_weight": 2.0,
        "A_weight": 1.8,
        "criticality_bonus": 25,
    },
    "cloud_hosted": {
        "label": "Cloud Hosted",
        "desc": "Cloud-hosted system — multi-tenant environment with shared infrastructure concerns",
        "C_weight": 1.5,
        "I_weight": 1.2,
        "A_weight": 1.0,
        "criticality_bonus": 5,
    },
    "custom": {
        "label": "Custom",
        "desc": "User-defined system type with standard baseline weights",
        "C_weight": 1.0,
        "I_weight": 1.0,
        "A_weight": 1.0,
        "criticality_bonus": 0,
    },
}

SYSTEM_TYPE_OPTIONS = [(k, v["label"]) for k, v in SYSTEM_TYPES.items()]
