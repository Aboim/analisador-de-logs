import re
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LogEntry:
    line_number: int
    timestamp: str = ""
    level: str = "INFO"
    source: str = ""
    message: str = ""
    raw_line: str = ""
    is_json: bool = False
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "line_number": self.line_number,
            "timestamp": self.timestamp,
            "level": self.level,
            "source": self.source,
            "message": self.message,
            "raw_line": self.raw_line,
            "is_json": self.is_json,
            "extra": self.extra,
        }


class LogParser:
    LOG_LEVELS = {"DEBUG", "INFO", "NOTICE", "WARNING", "WARN", "ERROR", "ERR",
                  "CRITICAL", "FATAL", "ALERT", "EMERGENCY", "TRACE", "VERBOSE"}

    TIMESTAMP_PATTERNS = [
        (re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'), "ISO8601"),
        (re.compile(r'^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}'), "YMD HMS"),
        (re.compile(r'^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}'), "DMY HMS"),
        (re.compile(r'^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}'), "Syslog"),
        (re.compile(r'^[A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}'), "Apache"),
        (re.compile(r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\]'), "BracketISO"),
        (re.compile(r'^\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}'), "DMONYYYY"),
        (re.compile(r'^\d{10,13}'), "UnixTimestamp"),
    ]

    SYSLOG_PATTERN = re.compile(
        r'^(?:<\d+>)?'  
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})?\s*'
        r'(\S+)?\s+'
        r'(\S+?)(?:\[(\d+)\])?:\s*'
        r'(.*)$'
    )

    APACHE_ACCESS_PATTERN = re.compile(
        r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
    )

    APACHE_ERROR_PATTERN = re.compile(
        r'^\[([^\]]+)\] \[(\w+):(\w+)\] \[pid (\d+)(?::tid (\d+))?\] (.*)$'
    )

    def __init__(self):
        pass

    def parse_file(self, filepath: str) -> list[LogEntry]:
        entries = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    entry = self.parse_line(line, i)
                    entries.append(entry)
        except Exception as e:
            print(f"Error reading file: {e}")
        return entries

    def parse_lines(self, lines: list[str]) -> list[LogEntry]:
        entries = []
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            entry = self.parse_line(line, i)
            entries.append(entry)
        return entries

    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        entry = LogEntry(line_number=line_number, raw_line=line)

        if line.startswith("{") or line.startswith("["):
            parsed = self._try_parse_json(line, entry)
            if parsed:
                return parsed

        timestamp, remainder = self._extract_timestamp(line)
        if timestamp:
            entry.timestamp = timestamp
            line = remainder.strip()

        line, entry = self._extract_level(line, entry)

        source_re = re.compile(r'^\[(\w+)\]\s*(?::\s*)?')
        sm = source_re.match(line)
        if sm:
            entry.source = sm.group(1)
            line = line[sm.end():].strip()

        if entry.source:
            entry.message = line
        elif ":" in line:
            parts = line.split(":", 1)
            potential_source = parts[0].strip()
            if not any(c in potential_source for c in " ./\n\t\r") and len(potential_source) < 40:
                entry.source = potential_source
                entry.message = parts[1].strip() if len(parts) > 1 else ""
            else:
                entry.message = line
        else:
            entry.message = line

        if entry.message.startswith(": "):
            entry.message = entry.message[2:]

        return entry

    def _try_parse_json(self, line: str, entry: LogEntry) -> Optional[LogEntry]:
        try:
            data = self._safe_json_parse(line)
            if data is None:
                return None
            if isinstance(data, dict):
                entry.is_json = True
                entry.timestamp = data.get("timestamp", data.get("time", data.get("@timestamp", data.get("datetime", ""))))
                entry.level = data.get("level", data.get("severity", data.get("log_level", data.get("loglevel", "INFO")))).upper()
                entry.source = data.get("logger", data.get("source", data.get("service", data.get("component", ""))))
                entry.message = data.get("message", data.get("msg", data.get("text", data.get("content", line))))
                entry.extra = {k: v for k, v in data.items()
                               if k not in ("timestamp", "time", "@timestamp", "datetime",
                                            "level", "severity", "log_level", "loglevel",
                                            "logger", "source", "service", "component",
                                            "message", "msg", "text", "content")}
                if not entry.timestamp:
                    entry.timestamp = self._find_timestamp_in_dict(data)
                return entry
        except Exception:
            pass
        return None

    def _safe_json_parse(self, line: str):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _find_timestamp_in_dict(self, data: dict) -> str:
        for key, value in data.items():
            if isinstance(value, str) and self._looks_like_timestamp(value):
                return value
        return ""

    def _looks_like_timestamp(self, s: str) -> bool:
        return bool(re.match(r'^\d{2,4}[-/]\d{2}[-/]\d{2,4}[T ]\d{2}:\d{2}', s)) or \
               bool(re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', s))

    def _extract_timestamp(self, line: str) -> tuple[str, str]:
        for pattern, _ in self.TIMESTAMP_PATTERNS:
            m = pattern.match(line)
            if m:
                ts = m.group(0)
                if ts.isdigit() and len(ts) >= 10:
                    try:
                        ts_int = int(ts[:10]) if len(ts) <= 10 else int(ts[:10])
                        dt = datetime.fromtimestamp(ts_int)
                        return dt.strftime("%Y-%m-%d %H:%M:%S"), line[len(ts):].strip()
                    except (ValueError, OSError):
                        pass
                return ts, line[len(ts):].strip()
        return "", line

    def _extract_level(self, line: str, entry: LogEntry) -> tuple[str, LogEntry]:
        level_re = re.compile(
            r'^(?:\[)?\s*(DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|ERR|CRITICAL|FATAL|ALERT|EMERGENCY|TRACE|VERBOSE)\s*(?:\])?(?:\s+|\s*:?\s*)',
            re.IGNORECASE
        )
        m = level_re.match(line)
        if m:
            entry.level = m.group(1).upper()
            if entry.level == "ERR":
                entry.level = "ERROR"
            if entry.level == "WARN":
                entry.level = "WARNING"
            line = line[m.end():].strip()
        return line, entry

    @staticmethod
    def is_error_line(entry: LogEntry) -> bool:
        error_levels = {"ERROR", "ERR", "CRITICAL", "FATAL", "EMERGENCY", "ALERT"}
        if entry.level.upper() in error_levels:
            return True
        error_keywords = ["error", "fail", "exception", "traceback", "fatal", "panic",
                          "refused", "timeout", "abort", "segfault", "crash"]
        msg_lower = entry.message.lower()[:200]
        return any(kw in msg_lower for kw in error_keywords)

    @staticmethod
    def is_warning_line(entry: LogEntry) -> bool:
        if entry.level.upper() in ("WARNING", "WARN"):
            return True
        warn_keywords = ["warn", "deprecated", "retry"]
        msg_lower = entry.message.lower()[:200]
        return any(kw in msg_lower for kw in warn_keywords)
