from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class IOC:
    """Represents an Indicator of Compromise extracted by MORPHEUS."""

    value: str
    ioc_type: str

    source: str
    session_id: Optional[str] = None

    confidence: float = 1.0
    context: List[str] = field(default_factory=list)

    def add_context(self, evidence: str) -> None:
        """Add supporting evidence for this IOC."""

        if evidence and evidence not in self.context:
            self.context.append(evidence)
