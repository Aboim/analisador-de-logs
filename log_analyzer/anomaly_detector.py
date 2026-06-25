import re
from typing import Optional
from datetime import datetime, timedelta
from collections import Counter


class AnomalyDetector:
    SUSPICIOUS_PATTERNS = [
        (re.compile(r'(?:stack\s*trace|traceback)', re.IGNORECASE), "Stack trace detected", "high"),
        (re.compile(r'(?:segmentation\s*fault|segfault)', re.IGNORECASE), "Segmentation fault", "critical"),
        (re.compile(r'(?:out\s*of\s*memory|OOM)', re.IGNORECASE), "Out of memory", "critical"),
        (re.compile(r'(?:connection\s*refused|connect\s*refused)', re.IGNORECASE), "Connection refused", "high"),
        (re.compile(r'(?:permission\s*denied|access\s*denied)', re.IGNORECASE), "Permission denied", "high"),
        (re.compile(r'(?:unauthorized|forbidden)', re.IGNORECASE), "Auth failure", "medium"),
        (re.compile(r'(?:null\s*pointer|NullPointerException)', re.IGNORECASE), "Null pointer", "high"),
        (re.compile(r'(?:core\s*dump|core\s*dumped)', re.IGNORECASE), "Core dump", "critical"),
        (re.compile(r'(?:kernel\s*panic|system\s*halt)', re.IGNORECASE), "Kernel panic", "critical"),
        (re.compile(r'(?:disk\s*full|no\s*space)', re.IGNORECASE), "Disk full", "critical"),
        (re.compile(r'(?:rate\s*limit|throttl)', re.IGNORECASE), "Rate limited", "medium"),
        (re.compile(r'(?:certificate\s*expir|SSL\s*error)', re.IGNORECASE), "SSL/Cert error", "high"),
        (re.compile(r'(?:injection|XSS|CSRF|SQLi)', re.IGNORECASE), "Security threat", "critical"),
        (re.compile(r'(?:brute\s*force)', re.IGNORECASE), "Brute force attempt", "high"),
        (re.compile(r'(?:panic|goroutine\s*panic)', re.IGNORECASE), "Panic", "critical"),
        (re.compile(r'(?:deadlock)', re.IGNORECASE), "Deadlock detected", "critical"),
    ]

    def __init__(self):
        self.baseline: dict = {}
        self.error_rate_history: list[tuple[str, float]] = []

    @staticmethod
    def _entry_attr(entry, attr: str, default: str = ""):
        if hasattr(entry, attr):
            return getattr(entry, attr, default) or default
        return entry.get(attr, default) if isinstance(entry, dict) else default

    def detect(self, entry, pattern_id: int = 0, similar_patterns: Optional[list] = None) -> tuple[bool, str, str, float]:
        message = self._entry_attr(entry, 'message', '')
        level = self._entry_attr(entry, 'level', '')
        raw_line = self._entry_attr(entry, 'raw_line', '')

        score = 0.0
        reasons = []

        if not pattern_id or pattern_id == 0:
            reasons.append("Unknown pattern (new log type)")
            score += 0.4

        for pattern, reason, severity in self.SUSPICIOUS_PATTERNS:
            if pattern.search(message) or pattern.search(raw_line):
                reasons.append(reason)
                score += 0.6
                break

        level_upper = level.upper() if level else ""
        if level_upper in ("CRITICAL", "FATAL", "EMERGENCY", "ALERT"):
            reasons.append(f"Critical level: {level_upper}")
            score += 0.7
        elif level_upper in ("ERROR", "ERR"):
            reasons.append("Error level log")
            score += 0.3

        if len(message) > 2000:
            reasons.append("Unusually long message")
            score += 0.2

        if message.count("\n") > 10:
            reasons.append("Multi-line/stack trace content")
            score += 0.3

        binary_chars = sum(1 for c in message if ord(c) < 32 and c not in '\n\r\t')
        if binary_chars > 5:
            reasons.append("Contains binary/non-printable characters")
            score += 0.3

        url_count = len(re.findall(r'https?://', message))
        if url_count > 5:
            reasons.append(f"Unusual number of URLs ({url_count})")
            score += 0.2

        is_anomaly = score >= 0.4
        severity = self._score_to_severity(score)
        reason_str = "; ".join(reasons) if reasons else "General anomaly"

        return is_anomaly, reason_str, severity, min(score, 1.0)

    def build_baseline(self, entries: list, db) -> dict:
        level_counts = Counter()
        source_counts = Counter()
        total = len(entries)

        for entry in entries:
            level = self._entry_attr(entry, 'level', '')
            source = self._entry_attr(entry, 'source', '')
            level_counts[level.upper()] += 1
            if source:
                source_counts[source] += 1

        error_count = level_counts.get("ERROR", 0) + level_counts.get("CRITICAL", 0) + level_counts.get("FATAL", 0)
        error_rate = error_count / total if total > 0 else 0

        self.baseline = {
            "total_lines": total,
            "level_distribution": dict(level_counts.most_common(10)),
            "top_sources": dict(source_counts.most_common(10)),
            "error_rate": error_rate,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return self.baseline

    def compare_to_baseline(self, entries: list) -> list[dict]:
        if not self.baseline:
            return []

        level_counts = Counter()
        for entry in entries:
            level = self._entry_attr(entry, 'level', '')
            level_counts[level.upper()] += 1

        total = len(entries)
        error_count = level_counts.get("ERROR", 0) + level_counts.get("CRITICAL", 0) + level_counts.get("FATAL", 0)
        current_error_rate = error_count / total if total > 0 else 0

        alerts = []
        baseline_error_rate = self.baseline.get("error_rate", 0)

        if baseline_error_rate > 0 and current_error_rate > baseline_error_rate * 2:
            alerts.append({
                "type": "error_rate_spike",
                "message": f"Error rate spike: {current_error_rate:.1%} vs baseline {baseline_error_rate:.1%}",
                "severity": "high",
            })

        if current_error_rate > baseline_error_rate * 5:
            alerts.append({
                "type": "error_rate_critical",
                "message": f"Critical error rate: {current_error_rate:.1%}",
                "severity": "critical",
            })

        unknown_levels = set(level_counts.keys()) - set(self.baseline.get("level_distribution", {}).keys())
        for lvl in unknown_levels:
            alerts.append({
                "type": "new_level",
                "message": f"New log level detected: {lvl}",
                "severity": "low",
            })

        return alerts

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"
