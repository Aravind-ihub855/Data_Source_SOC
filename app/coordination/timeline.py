import datetime
from typing import Optional
from app.util import now, iso


class TimelineManager:
    """
    Manages synchronized scenario attack clocks, staged offsets, and out-of-order jitter.
    The base time comes from the shared clock, so backfills run on simulated time.
    """
    def __init__(self, base_time: Optional[datetime.datetime] = None):
        self.base_time: datetime.datetime = base_time or now()

    def get_time_at_offset(
        self,
        offset_seconds: float = 0.0,
        jitter_seconds: float = 0.0
    ) -> str:
        """
        Returns ISO-8601 UTC timestamp string at a specific delta offset from scenario base time.
        """
        return iso(self.base_time + datetime.timedelta(seconds=offset_seconds + jitter_seconds))

    def get_out_of_order_time(
        self,
        negative_offset_seconds: float = 120.0
    ) -> str:
        """
        Generates late-arriving or reversed timestamp for data quality testing.
        """
        return iso(self.base_time - datetime.timedelta(seconds=negative_offset_seconds))
