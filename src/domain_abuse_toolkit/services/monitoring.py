from __future__ import annotations

import threading
from datetime import UTC, datetime

from domain_abuse_toolkit.models import CaseState
from domain_abuse_toolkit.services.cases import CaseService
from domain_abuse_toolkit.services.collection_jobs import (
    CollectionAlreadyRunningError,
    CollectionJobService,
    CollectionQueueFullError,
)
from domain_abuse_toolkit.services.follow_up import next_monitoring_due_at


class MonitoringScheduler:
    """Run explicitly authorized, bounded DNS/HTTP/TLS checks while the app is open."""

    def __init__(
        self,
        case_service: CaseService,
        collection_jobs: CollectionJobService,
        *,
        enabled: bool,
        poll_seconds: float = 30,
    ) -> None:
        self.case_service = case_service
        self.collection_jobs = collection_jobs
        self.enabled = enabled
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self.enabled or (self._thread and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="dat-monitoring-scheduler",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=min(self.poll_seconds + 1, 5))

    def poll_once(self, now: datetime | None = None) -> list[str]:
        if not self.enabled:
            return []
        current_time = now or datetime.now(UTC)
        started: list[str] = []
        terminal_states = {
            CaseState.MITIGATED,
            CaseState.CLOSED,
            CaseState.FALSE_POSITIVE,
            CaseState.TRANSFERRED,
        }
        for record in self.case_service.list():
            if not record.monitoring_enabled or record.state in terminal_states:
                continue
            due_at = next_monitoring_due_at(record)
            if due_at is None or due_at > current_time:
                continue
            try:
                self.collection_jobs.start_monitor(record.id)
            except (CollectionAlreadyRunningError, CollectionQueueFullError):
                continue
            started.append(record.id)
        return started

    def _run(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.poll_seconds)
