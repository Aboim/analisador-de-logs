import re
import hashlib
from typing import Optional


class PatternLearner:
    TOKEN_PATTERNS = [
        (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b'), "{IP}"),
        (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), "{IPV6}"),
        (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), "{UUID}"),
        (re.compile(r'\b[0-9a-fA-F]{32,128}\b'), "{HASH}"),
        (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "{EMAIL}"),
        (re.compile(r'(?:https?|ftp|ws)s?://\S+'), "{URL}"),
        (re.compile(r'(?:/[\w./-]+)+\.\w{1,6}'), "{PATH}"),
        (re.compile(r'[A-Z]:\\(?:[\w .-]+\\)*[\w .-]+\.\w+'), "{WINPATH}"),
        (re.compile(r'\b0x[0-9a-fA-F]+\b'), "{HEX}"),
        (re.compile(r'\b\d{2,4}[-/]\d{2}[-/]\d{2,4}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'), "{DATE}"),
        (re.compile(r'\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b'), "{SYSDATE}"),
        (re.compile(r'\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\]'), "{BRACKETDATE}"),
        (re.compile(r'\b\d+\.\d+\.\d+(?:[-.]\w+)*\b'), "{VERSION}"),
        (re.compile(r'\b\d{4,6}\b'), "{PORT}"),
        (re.compile(r'\b[a-fA-F0-9]{6,8}\b'), "{HEXCOLOR}"),
        (re.compile(r'\d+'), "{NUM}"),
    ]

    ERROR_KEYWORDS = {"error", "fail", "exception", "fatal", "panic", "critical",
                      "refused", "timeout", "abort", "segfault", "crash", "traceback",
                      "denied", "unauthorized", "forbidden", "unavailable", "broken"}
    WARNING_KEYWORDS = {"warn", "deprecated", "retry", "slow", "timeout", "limit",
                        "exceeded", "throttle"}
    INFO_KEYWORDS = {"start", "init", "loaded", "ready", "listening", "connected",
                     "completed", "success", "ok", "healthy", "alive"}
    DEBUG_KEYWORDS = {"trace", "debug", "verbose", "dump", "detail"}

    def __init__(self):
        pass

    def generate_signature(self, message: str) -> str:
        clean = message.strip()
        clean = re.sub(r'\s+', ' ', clean)
        for pattern, replacement in self.TOKEN_PATTERNS:
            clean = pattern.sub(replacement, clean)
        clean = re.sub(r'{NUM}(\s*\.\s*{NUM})+', '{NUM}', clean)
        clean = re.sub(r'[ \t]+', ' ', clean)
        return clean.strip()

    def classify_category(self, message: str, level: str = "") -> str:
        msg_lower = message.lower()
        level_upper = level.upper() if level else ""

        if level_upper in ("ERROR", "ERR", "CRITICAL", "FATAL", "EMERGENCY", "ALERT"):
            return "error"

        checks = [
            (self.ERROR_KEYWORDS, "error"),
            (self.WARNING_KEYWORDS, "warning"),
            (self.DEBUG_KEYWORDS, "debug"),
            (self.INFO_KEYWORDS, "info"),
        ]

        for keywords, cat in checks:
            for kw in keywords:
                if kw in msg_lower:
                    return cat

        if level_upper in ("WARNING", "WARN"):
            return "warning"
        if level_upper == "DEBUG":
            return "debug"
        if level_upper == "TRACE":
            return "debug"

        if any(kw in msg_lower for kw in ["http", "request", "response", "status",
                                            "get", "post", "put", "delete", "api"]):
            return "http"
        if any(kw in msg_lower for kw in ["sql", "database", "query", "table", "row",
                                            "insert", "select", "update"]):
            return "database"
        if any(kw in msg_lower for kw in ["cpu", "memory", "disk", "io", "throughput",
                                            "latency", "bytes", "cache"]):
            return "system"
        if any(kw in msg_lower for kw in ["login", "auth", "user", "password", "token",
                                            "session", "credential"]):
            return "auth"

        return "unknown"

    def is_error_pattern(self, message: str, level: str = "") -> bool:
        level_upper = level.upper() if level else ""
        if level_upper in ("ERROR", "ERR", "CRITICAL", "FATAL", "EMERGENCY", "ALERT"):
            return True
        return any(kw in message.lower() for kw in self.ERROR_KEYWORDS)

    def signature_hash(self, signature: str) -> str:
        return hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16]

    def build_regex(self, signature: str) -> str:
        escaped = re.escape(signature)
        placeholders = {
            r"\{IP\}": r'(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?',
            r"\{IPV6\}": r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
            r"\{UUID\}": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            r"\{HASH\}": r'[0-9a-fA-F]{32,128}',
            r"\{EMAIL\}": r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',
            r"\{URL\}": r'(?:https?|ftp|ws)s?://\S+',
            r"\{PATH\}": r'(?:/[\w./-]+)+\.\w{1,6}',
            r"\{WINPATH\}": r'[A-Z]:\\(?:[\w .-]+\\)*[\w .-]+\.\w+',
            r"\{HEX\}": r'0x[0-9a-fA-F]+',
            r"\{DATE\}": r'\d{2,4}[-/]\d{2}[-/]\d{2,4}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?',
            r"\{SYSDATE\}": r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
            r"\{BRACKETDATE\}": r'\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\]',
            r"\{VERSION\}": r'\d+\.\d+\.\d+(?:[-.]\w+)*',
            r"\{PORT\}": r'\d{4,6}',
            r"\{HEXCOLOR\}": r'[a-fA-F0-9]{6,8}',
            r"\{NUM\}": r'\d+',
        }
        for placeholder, regex in placeholders.items():
            escaped = escaped.replace(placeholder, regex)
        return f"^{escaped}$"

    def match_pattern(self, message: str, regex_pattern: str) -> bool:
        try:
            return bool(re.match(regex_pattern, message))
        except re.error:
            return False

    @staticmethod
    def _entry_attr(entry, attr: str, default: str = ""):
        if hasattr(entry, attr):
            return getattr(entry, attr) or default
        return entry.get(attr, default) if isinstance(entry, dict) else default

    def learn_from_entries(self, entries: list, db) -> dict:
        stats = {"new_patterns": 0, "matched": 0, "total": len(entries)}
        existing_patterns = db.get_all_patterns()
        pattern_cache = {}
        for p in existing_patterns:
            pattern_cache[p["signature"]] = p

        for entry in entries:
            message = self._entry_attr(entry, 'message', '')
            if not message.strip():
                continue

            signature = self.generate_signature(message)

            if signature in pattern_cache:
                cached = pattern_cache[signature]
                db.update_pattern_frequency(cached["id"])
                if hasattr(entry, 'to_dict'):
                    entry.pattern_id = cached["id"]
                else:
                    entry["pattern_id"] = cached["id"]
                stats["matched"] += 1
                continue

            level = self._entry_attr(entry, 'level')
            category = self.classify_category(message, level)
            is_error = self.is_error_pattern(message, level)
            regex_pattern = self.build_regex(signature)
            pattern_id = db.add_pattern(
                signature=signature,
                regex_pattern=regex_pattern,
                category=category,
                sample=message[:500],
                is_error=is_error,
            )
            if pattern_id:
                pattern_cache[signature] = {"id": pattern_id, "signature": signature}
                stats["new_patterns"] += 1
                if hasattr(entry, 'to_dict'):
                    entry.pattern_id = pattern_id
                else:
                    entry["pattern_id"] = pattern_id

        return stats

    def get_similar_patterns(self, message: str, db,
                             threshold: float = 0.7) -> list[dict]:
        signature = self.generate_signature(message)
        tokens = set(signature.split())
        all_patterns = db.get_all_patterns()
        similar = []

        for p in all_patterns:
            p_tokens = set(p["signature"].split())
            if not p_tokens:
                continue
            common = tokens & p_tokens
            score = len(common) / max(len(tokens), len(p_tokens))
            if score >= threshold:
                similar.append({**p, "similarity": round(score, 2)})

        similar.sort(key=lambda x: x["similarity"], reverse=True)
        return similar[:10]

    def auto_review_pattern(self, signature: str, db,
                            min_frequency: int = 3) -> bool:
        pattern = db.find_pattern_by_signature(signature)
        if pattern and pattern["frequency"] >= min_frequency and not pattern["confirmed"]:
            db.update_pattern_confirm(pattern["id"], True)
            return True
        return False
