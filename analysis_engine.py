"""Format-agnostic, explainable log triage helpers.

Scores are heuristic priority scores (0-100), not probabilities or a replacement
for a system-specific baseline, alerting policy, or incident response process.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any


_SEVERITY_PATTERNS = [
    ("CRITICAL", re.compile(r"\b(?:emerg(?:ency)?|alert|crit(?:ical)?|fatal|panic|kernel panic|out of memory|oom-kill|segfault|segmentation fault)\b", re.I)),
    ("ERROR", re.compile(r"\b(?:error|err|failed|failure|exception|traceback|denied|refused|unavailable|corrupt(?:ion)?)\b", re.I)),
    ("WARNING", re.compile(r"\b(?:warn(?:ing)?|degrad(?:ed|ation)|retry(?:ing)?|throttl(?:ed|ing)|deprecated)\b", re.I)),
    ("INFO", re.compile(r"\b(?:info(?:rmational)?|notice)\b", re.I)),
    ("DEBUG", re.compile(r"\b(?:debug|trace|verbose)\b", re.I)),
]

# Deliberately broad signatures: match common Linux, network, database,
# application, container, and web-server language without assuming one vendor.
_CATEGORY_RULES = [
    ("Resource exhaustion", re.compile(r"\b(?:out of memory|oom|memory exhausted|cannot allocate memory|no space left on device|disk full|disk quota|resource exhausted|too many open files|file descriptor limit)\b", re.I),
     "A resource limit may have been reached.", "Check host/container memory, disk and inode usage, process limits, and recent workload growth. Preserve diagnostic data before restarting anything."),
    ("Service or process failure", re.compile(r"\b(?:service (?:is )?(?:down|failed|stopped)|process (?:exited|crashed|terminated)|crash(?:ed)?|segfault|segmentation fault|failed to start|start(?:up)? failed|worker.{0,30}(?:failed|crash|error)|exit code [1-9])\b", re.I),
     "A process or service may have failed to start or remain healthy.", "Check the service manager/container status and the surrounding log lines for the first failure. Validate recent configuration or deployment changes before restarting."),
    ("Database or storage", re.compile(r"\b(?:deadlock|database|db connection|connection pool|sqlstate|postgres(?:ql)?|mysql|mongodb|redis|replica lag|transaction rollback|lock wait|too many connections)\b", re.I),
     "The message appears related to a database, datastore, or persistence layer.", "Check datastore health, connection limits, replication/lock status, and the exact error code. Avoid retrying non-idempotent operations until their outcome is known."),
    ("Timeout or latency", re.compile(r"\b(?:upstream timed out|timed? out|timeout|deadline exceeded|latency|took too long|slow query|request duration exceeded)\b", re.I),
     "An operation exceeded its expected time limit.", "Identify which operation timed out, its duration, and the affected dependency. Check load, queues, and network/service latency before increasing timeouts."),
    ("Network or connectivity", re.compile(r"\b(?:connection (?:timed? out|reset|refused|closed)|network is unreachable|no route to host|broken pipe|socket error|host is down|econn(?:refused|reset|timeout)|etimedout)\b", re.I),
     "A network connection or remote endpoint may be unavailable or unstable.", "Verify the destination, DNS, routing, firewall/security rules, and endpoint health from the affected host. Compare timestamps across both ends if possible."),
    ("DNS resolution", re.compile(r"\b(?:dns|name or service not known|temporary failure in name resolution|could not resolve|no such host|nxdomain|servfail)\b", re.I),
     "The host name may not be resolving, or the DNS service may be unhealthy.", "Check the queried name, resolver configuration, DNS response/TTL, and reachability of configured resolvers."),
    ("TLS or certificate", re.compile(r"\b(?:ssl|tls|certificate|cert expired|x509|handshake failure|unknown ca|certificate verify failed|hostname mismatch)\b", re.I),
     "A TLS handshake or certificate validation problem is indicated.", "Check certificate validity dates, hostname/SAN, trust chain, system clock, and TLS compatibility on both endpoints. Do not disable certificate validation as a workaround."),
    ("Authentication or authorization", re.compile(r"\b(?:authentication failed|auth failed|failed password|invalid user|invalid credentials|login failed|unauthori[sz]ed|permission denied|access denied|forbidden|account locked|invalid token|token expired|sudo:.*authentication)\b", re.I),
     "An identity, credential, or permission check failed.", "Confirm the intended account/service identity, credential rotation status, role/ACL, and source of the request. For repeated failures, review access logs and follow your security process."),
    ("HTTP or application request", re.compile(r"\b(?:http(?:/\d(?:\.\d)?)?\s+[45]\d\d|\bstatus[=: ]+[45]\d\d\b|\b[45]\d\d\s+(?:\w+\s+)?(?:request|response|error)|bad gateway|service unavailable|internal server error|request failed)\b", re.I),
     "An application or web request appears to have failed.", "Correlate the request ID and timestamp with application and upstream logs. Check the response code, dependency health, and recent releases before changing configuration."),
    ("Configuration or parsing", re.compile(r"\b(?:invalid configuration|config(?:uration)? error|syntax error|parse error|failed to parse|unknown directive|missing required|invalid argument|malformed)\b", re.I),
     "A configuration value or input may be invalid or incomplete.", "Inspect the exact field/file and validate configuration with the component's built-in checker. Compare against the last known-good version before applying changes."),
    ("Kernel or hardware", re.compile(r"\b(?:kernel:|kernel panic|i/o error|hardware error|machine check|read-only file system|filesystem error|nvme|scsi error)\b", re.I),
     "The message may originate from the kernel, filesystem, or hardware layer.", "Check kernel/system journal entries around the same time and inspect storage/device health. Escalate persistent I/O or hardware errors; avoid filesystem repair while mounted."),
]

_BASE_SCORE = {"CRITICAL": 98.0, "ERROR": 78.0, "WARNING": 52.0, "INFO": 8.0, "DEBUG": 4.0, "UNKNOWN": 14.0}


def normalize_template(line: str) -> str:
    """Normalize volatile fields so similar log events share a template."""
    text = line.lower()
    text = re.sub(r"\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:?\d{2})?\b", "<timestamp>", text)
    text = re.sub(r"\b\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\d{4}\b", "<timestamp>", text)
    text = re.sub(r"\b\d{4}/\d{2}/\d{2}[ :]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b", "<timestamp>", text)
    text = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", text)
    text = re.sub(r"\b[0-9a-f]{12,}\b", "<hex>", text)
    text = re.sub(r"\b\d+\b", "<n>", text)
    return re.sub(r"\s+", " ", text).strip()


_NGRAM_TOKEN_PATTERN = re.compile(r"<[^>]+>|[a-z]+(?:[._:/-][a-z0-9]+)*|\d+", re.I)


def ngram_anomaly_scores(lines: list[str], n: int = 3) -> list[float]:
    """Score sequence novelty with a smoothed, leave-one-out N-gram model.

    The submitted batch is the local reference corpus. Each line is scored
    against the other lines, so a line does not make its own sequence look
    common. The result is a small 0-20 supporting signal, not a probability.
    Small batches return zero because they do not provide enough context for a
    useful language model.
    """
    if len(lines) < 5 or n < 2:
        return [0.0 for _ in lines]
    token_lines = []
    for line in lines:
        template = normalize_template(line)
        tokens = _NGRAM_TOKEN_PATTERN.findall(template)
        token_lines.append(["<s>"] * (n - 1) + tokens + ["</s>"])

    all_ngrams: Counter[tuple[str, ...]] = Counter()
    all_prefixes: Counter[tuple[str, ...]] = Counter()
    line_ngrams: list[Counter[tuple[str, ...]]] = []
    line_prefixes: list[Counter[tuple[str, ...]]] = []
    vocabulary: set[str] = set()
    for tokens in token_lines:
        vocabulary.update(tokens)
        grams = Counter(tuple(tokens[index:index + n]) for index in range(len(tokens) - n + 1))
        prefixes = Counter(tuple(tokens[index:index + n - 1]) for index in range(len(tokens) - n + 1))
        line_ngrams.append(grams)
        line_prefixes.append(prefixes)
        all_ngrams.update(grams)
        all_prefixes.update(prefixes)

    vocabulary_size = max(len(vocabulary), 1)
    average_surprisal: list[float] = []
    for index, grams in enumerate(line_ngrams):
        if not grams:
            average_surprisal.append(0.0)
            continue
        surprise_total = 0.0
        event_count = 0
        for gram, occurrences in grams.items():
            prefix = gram[:-1]
            gram_count = all_ngrams[gram] - occurrences
            prefix_count = all_prefixes[prefix] - line_prefixes[index][prefix]
            probability = (gram_count + 1.0) / (prefix_count + vocabulary_size)
            surprise_total += occurrences * (-math.log(probability))
            event_count += occurrences
        average_surprisal.append(surprise_total / max(event_count, 1))

    usable = sorted(value for value in average_surprisal if value > 0)
    if not usable:
        return [0.0 for _ in lines]
    baseline = usable[len(usable) // 2]
    return [round(min(20.0, max(0.0, 12.0 * (value / max(baseline, 1e-9) - 1.0))), 1) for value in average_surprisal]


def _severity(line: str) -> str:
    # RFC 5424 syslog PRI values encode severity in the low three bits.
    pri = re.search(r"^\s*<(\d{1,3})>", line)
    if pri and int(pri.group(1)) <= 191:
        return {0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR", 4: "WARNING", 5: "INFO", 6: "INFO", 7: "DEBUG"}[int(pri.group(1)) % 8]
    # Explicit severity fields/labels take precedence over words in the message.
    label_match = re.search(r"\[(emerg(?:ency)?|alert|crit(?:ical)?|fatal|panic|error|err|warn(?:ing)?|notice|info(?:rmational)?|debug|trace)\]", line, re.I)
    if not label_match:
        label_match = re.search(r"\b(?:severity|level)\s*[=:]\s*[\"']?(emerg(?:ency)?|alert|crit(?:ical)?|fatal|panic|error|err|warn(?:ing)?|notice|info(?:rmational)?|debug|trace)\b", line, re.I)
    if label_match:
        label = label_match.group(1).lower()
        if label in {"emerg", "emergency", "alert", "crit", "critical", "fatal", "panic"}:
            return "CRITICAL"
        if label in {"error", "err"}:
            return "ERROR"
        if label in {"warn", "warning"}:
            return "WARNING"
        if label == "notice" or label.startswith("info"):
            return "INFO"
        return "DEBUG"
    # Structured numeric level/severity fields (0 emergency through 7 debug).
    match = re.search(r"\b(?:severity|level)\s*[=:]\s*(\d)\b", line, re.I)
    if match:
        return {"0": "CRITICAL", "1": "CRITICAL", "2": "CRITICAL", "3": "ERROR", "4": "WARNING", "5": "INFO", "6": "INFO", "7": "DEBUG"}[match.group(1)]
    if re.search(r"\b(?:failed password|invalid user|authentication failure|login failed)\b", line, re.I):
        return "WARNING"
    for severity, pattern in _SEVERITY_PATTERNS:
        if pattern.search(line):
            return severity
    # HTTP response status codes are strong evidence of request failure.
    if re.search(r"\b(?:status[=: ]+|HTTP/\d(?:\.\d)?\s+)[45]\d\d\b", line, re.I):
        return "ERROR"
    return "UNKNOWN"


def _diagnosis(line: str, severity: str) -> dict[str, str]:
    for category, pattern, explanation, action in _CATEGORY_RULES:
        if pattern.search(line):
            return {"category": category, "explanation": explanation, "action": action}
    if severity == "CRITICAL":
        return {"category": "Critical system/application event", "explanation": "The message contains a critical/fatal indicator, but no more specific known signature matched.", "action": "Treat this as urgent. Check nearby events and the affected component's health, then follow your incident response/runbook. The exact cause is not determined from this line alone."}
    if severity == "ERROR":
        return {"category": "Unclassified error", "explanation": "The line is marked or worded as an error, but does not match a more specific supported pattern.", "action": "Review surrounding lines, request/event IDs, and the component's own error details. Check recent changes and use the official runbook before taking corrective action."}
    if severity == "WARNING":
        return {"category": "Warning", "explanation": "The line contains a warning/degradation indicator; it may be transient or may precede a failure.", "action": "Check whether the warning repeats, affects service metrics, or is followed by an error. Compare with the component's documented meaning."}
    return {"category": "Unusual or informational event", "explanation": "No known error signature was found. A rare log format by itself is not proof of a fault.", "action": "Monitor for repetition and correlate with service metrics or nearby events. If this is unexpected, consult the emitting component's documentation."}


def analyze_logs(lines: list[str], threshold: float = 60.0) -> list[dict[str, Any]]:
    """Analyze log lines with severity rules, rarity, and trigram novelty."""
    cleaned = [str(line).strip() for line in lines if str(line).strip()]
    templates = [normalize_template(line) for line in cleaned]
    ngram_scores = ngram_anomaly_scores(cleaned, n=3)
    counts = Counter(templates)
    max_count = max(counts.values(), default=1)
    batch_has_context = len(cleaned) >= 5
    results: list[dict[str, Any]] = []
    for index, (line, template) in enumerate(zip(cleaned, templates), start=1):
        severity = _severity(line)
        # Rarity is a small supporting signal only when there is enough batch context.
        rarity = (28.0 * (1.0 - counts[template] / max_count)) if batch_has_context else 0.0
        diagnosis = _diagnosis(line, severity)
        auth_review_boost = 15.0 if diagnosis["category"] == "Authentication or authorization" else 0.0
        ngram_score = ngram_scores[index - 1]
        score = min(100.0, round(_BASE_SCORE[severity] + rarity + auth_review_boost + ngram_score, 1))
        results.append({
            "line_number": index,
            "line": line,
            "template": template,
            "template_count": counts[template],
            "severity": severity,
            "score": score,
            "is_anomaly": score >= float(threshold),
            "rarity_score": round(rarity, 1),
            "ngram_score": ngram_score,
            "security_review_boost": round(auth_review_boost, 1),
            **diagnosis,
        })
    return results


def parse_uploaded_text(name: str, data: bytes) -> str:
    """Decode a supported text log; format is preserved as line-oriented text."""
    text = data.decode("utf-8-sig", errors="replace")
    if name.lower().endswith((".json", ".jsonl", ".ndjson")):
        import json
        if name.lower().endswith(".json"):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return "\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in parsed)
                if isinstance(parsed, dict):
                    # Common log envelope fields; if absent, preserve the record as one event.
                    events = parsed.get("events") or parsed.get("records") or parsed.get("logs")
                    if isinstance(events, list):
                        return "\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in events)
                    return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
            except json.JSONDecodeError:
                pass
    return text
