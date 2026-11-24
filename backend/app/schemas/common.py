from pydantic import BaseModel
from typing import Dict, Any, List

class MetricsResponse(BaseModel):
    total_alerts: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    mitigated_count: int
    in_progress_count: int
    new_count: int
    active_isolations: int
    avg_response_time_minutes: float
    threat_feed_status: Dict[str, str]
    severity_distribution: Dict[str, int]
    top_sources: Dict[str, int]
    mitre_tactics: Dict[str, int] = {}
    academic_benchmarks: Dict[str, Any] = {}
    top_targeted_assets: List[Dict[str, Any]] = []

class StatusMessage(BaseModel):
    status: str
    message: str
    data: Any = None
