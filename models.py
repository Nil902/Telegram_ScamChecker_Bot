from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """One concrete, explainable fact about a file or link.

    Produced only by deterministic code — never by the LLM.

    `params` holds values referenced by the Khmer template for this code,
    so the translated text can be a template (e.g. "…opens '{host}'") rather
    than a fixed sentence. `to_dict()` deliberately omits `params`: it is the
    shape handed to the agent, which must reason only about codes and plain
    English, never about template internals.
    """
    code: str                     # machine-readable, e.g. "FILENAME_EXECUTABLE"
    severity: Severity
    explanation: str              # plain English, later translated to Khmer
    params: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "explanation": self.explanation,
        }


@dataclass
class FileCheckResult:
    findings: list[Finding] = field(default_factory=list)
    conclusive: bool = False        # enough to decide with no download
    needs_inspection: bool = False  # ambiguous — agent should dig deeper

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "conclusive": self.conclusive,
            "needs_inspection": self.needs_inspection,
        }
