"""Central aggregation of campaign intelligence from multiple honeypots."""

from typing import Any, Dict, Iterable, List

from intelligence.campaign.detector import CampaignDetector
from intelligence.campaign.model import AttackCampaign
from intelligence.campaign.persistence import restore_campaign_context


class CrossHoneypotAggregator:
    """Rebuild campaigns from analysis events produced by multiple sensors."""

    def __init__(self) -> None:
        self.detector = CampaignDetector()

    @property
    def campaigns(self) -> Dict[str, AttackCampaign]:
        return self.detector.campaigns

    def rebuild(self, events: Iterable[Dict[str, Any]]) -> List[AttackCampaign]:
        self.detector = CampaignDetector()
        restore_campaign_context(
            detector=self.detector,
            events=events,
            namespace_sessions=True,
        )
        return list(self.detector.campaigns.values())
