import numpy as np
import pandas as pd
from typing import Dict, Any
from datetime import datetime


def determine_severity_score(result: Dict[str, Any]) -> str:
    """Severity: 1-Critical, 2-High, 3-Medium, 4-Low"""
    sev_labels = ["4-Low", "4-Low", "3-Medium", "2-High", "1-Critical"]

    def trurisk_adj(base, trurisk):
        if not trurisk:
            return base
        try:
            trurisk_val = float(trurisk) if not is_nan(trurisk) else 0
            if trurisk_val >= 800 and not base.startswith(("1-", "2-")):
                return "2-High"
            if trurisk_val >= 600 and base.startswith("4-"):
                return "3-Medium"
        except (ValueError, TypeError):
            pass
        return base

    if result.get("cve_results"):
        max_score = max(c.score for c in result["cve_results"])
        base = (
            "1-Critical"
            if max_score >= 9
            else (
                "2-High"
                if max_score >= 7
                else "3-Medium" if max_score >= 4 else "4-Low"
            )
        )
        return trurisk_adj(base, result["original_data"].get("TruRisk Score"))

    severity = result["original_data"].get("Severity")
    if not severity or is_nan(severity):
        return "Unknown"
    
    try:
        severity_val = int(float(str(severity)))
        base = sev_labels[min(max(severity_val, 1), 5) - 1]
        return trurisk_adj(base, result["original_data"].get("TruRisk Score"))
    except (ValueError, TypeError):
        return "Unknown"


def get_days_diff(start_str: str, end_str: str) -> int:
    """Calculate days difference with robust error handling"""
    if not start_str or not end_str or is_nan(start_str) or is_nan(end_str):
        return 0
        
    fmt = "%m-%d-%Y %H:%M"
    alt_fmt = "%m/%d/%Y %H:%M"
    
    try:
        # Try primary format
        start_date = datetime.strptime(str(start_str).strip(), fmt)
        end_date = datetime.strptime(str(end_str).strip(), fmt)
        return max(0, (end_date - start_date).days)
    except ValueError:
        try:
            # Try alternative format
            start_date = datetime.strptime(str(start_str).strip(), alt_fmt)
            end_date = datetime.strptime(str(end_str).strip(), alt_fmt)
            return max(0, (end_date - start_date).days)
        except ValueError:
            return 0


def is_nan(value):
    """Check if value is NaN/None/empty in a pandas-compatible way"""
    if value is None:
        return True
    if isinstance(value, float) and np.isnan(value):
        return True
    if isinstance(value, str) and value.lower().strip() in ["nan", "none", "", "nat"]:
        return True
    try:
        if pd.isna(value):
            return True
    except:
        pass
    return False


def clean_value(value, default=""):
    """Convert any NaN/None values to default with type safety"""
    if is_nan(value):
        return default
    try:
        return str(value).strip()
    except:
        return default


def safe_int_conversion(value, default=0):
    """Safely convert value to integer"""
    if is_nan(value):
        return default
    try:
        # Handle string representations of numbers
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return default
        return int(float(value))
    except (ValueError, TypeError):
        return default


def simplify_date(date):
    """Convert date string with robust NaN/None handling"""
    if is_nan(date):
        return ""
    
    date_str = clean_value(date)
    if not date_str:
        return ""
        
    try:
        # Handle multiple date formats
        for fmt in ("%m-%d-%Y %H:%M", "%m/%d/%Y %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt_obj = datetime.strptime(date_str, fmt)
                return f"{dt_obj.strftime('%B')} {dt_obj.day}, {dt_obj.year}"
            except ValueError:
                continue
        
        # If no format matched, try to extract at least the date part
        date_part = date_str.split()[0] if ' ' in date_str else date_str
        for fmt in ("%m-%d-%Y", "%m/%d/%Y", "%Y-%m-%d"):
            try:
                dt_obj = datetime.strptime(date_part, fmt)
                return f"{dt_obj.strftime('%B')} {dt_obj.day}, {dt_obj.year}"
            except ValueError:
                continue
                
        return date_str  # Return original if no format matched
    except (ValueError, TypeError):
        return ""


def determine_sla_status(severity_score: str, vulnerability_age) -> str:
    """Determine SLA status based on severity and age thresholds with robust type handling"""
    # Safely convert vulnerability_age to integer
    try:
        if is_nan(vulnerability_age):
            age_days = 0
        elif isinstance(vulnerability_age, str):
            age_days = safe_int_conversion(vulnerability_age.strip(), 0)
        else:
            age_days = safe_int_conversion(vulnerability_age, 0)
    except:
        age_days = 0

    if not severity_score or is_nan(severity_score):
        return "N/A - Needs Assessment"

    severity_str = clean_value(severity_score)
    
    # Define thresholds based on severity score prefixes
    thresholds = {
        "1-": ("Critical", 7),
        "2-": ("High", 14), 
        "3-": ("Medium", 30),
        "4-": ("Low", 90),
    }

    for prefix, (level, threshold_days) in thresholds.items():
        if severity_str.startswith(prefix):
            status = "Breached" if age_days > threshold_days else "Within SLA"
            return status

    return "N/A - Needs Assessment"

