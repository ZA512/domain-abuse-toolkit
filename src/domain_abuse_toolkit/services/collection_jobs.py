from __future__ import annotations

import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Protocol

from pydantic import BaseModel

from domain_abuse_toolkit.models import (
    CollectorError,
    CollectorResult,
    CollectorStatus,
    NormalizedTarget,
    SnapshotEvent,
)
from domain_abuse_toolkit.services.cases import CaseService
from domain_abuse_toolkit.services.collectors import CollectorOutput


class PassiveCollector(Protocol):
    version: str

    def collect(self, target: NormalizedTarget, snapshot_id: str) -> CollectorOutput: ...


class CollectionAlreadyRunningError(ValueError):
    pass


class CollectionQueueFullError(ValueError):
    pass


class CollectionJobView(BaseModel):
    id: str
    case_id: str
    snapshot_id: str
    status: CollectorStatus
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None


class CollectionJobService:
    """Small local executor; final snapshots are persisted, transient job state is not."""

    def __init__(
        self,
        case_service: CaseService,
        dns_collector: PassiveCollector,
        *,
        max_workers: int = 2,
        max_pending_jobs: int = 10,
    ) -> None:
        self.case_service = case_service
        self.dns_collector = dns_collector
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="dat-collector"
        )
        self._lock = threading.Lock()
        self._max_pending_jobs = max_pending_jobs
        self._jobs: dict[str, CollectionJobView] = {}
        self._futures: dict[str, Future[None]] = {}

    def start_dns(self, case_id: str) -> CollectionJobView:
        record = self.case_service.get(case_id)
        with self._lock:
            active_jobs = [
                job
                for job in self._jobs.values()
                if job.status in {CollectorStatus.QUEUED, CollectorStatus.RUNNING}
            ]
            if len(active_jobs) >= self._max_pending_jobs:
                raise CollectionQueueFullError(
                    "The passive collection queue has reached its configured limit."
                )
            if any(
                job.case_id == case_id
                and job.status in {CollectorStatus.QUEUED, CollectorStatus.RUNNING}
                for job in active_jobs
            ):
                raise CollectionAlreadyRunningError(
                    "A passive collection job is already running for this case."
                )
            job = CollectionJobView(
                id=f"JOB-{uuid.uuid4().hex.upper()}",
                case_id=case_id,
                snapshot_id=f"SNP-{uuid.uuid4().hex.upper()}",
                status=CollectorStatus.QUEUED,
                queued_at=datetime.now(UTC),
            )
            self._jobs[job.id] = job
            future = self._executor.submit(
                self._run_dns, job.id, record.target.model_copy(deep=True)
            )
            self._futures[job.id] = future
            return job.model_copy(deep=True)

    def _run_dns(self, job_id: str, target: NormalizedTarget) -> None:
        self._update(job_id, status=CollectorStatus.RUNNING, started_at=datetime.now(UTC))
        job = self.get(job_id)
        try:
            output = self.dns_collector.collect(target, job.snapshot_id)
        except Exception:  # collector boundary deliberately hides target-controlled details
            now = datetime.now(UTC)
            output = CollectorOutput(
                result=CollectorResult(
                    collector="dns",
                    version=self.dns_collector.version,
                    status=CollectorStatus.FAILED,
                    started_at=job.started_at or now,
                    finished_at=now,
                    errors=[
                        CollectorError(
                            code="collector_failure",
                            message="The DNS collector stopped unexpectedly.",
                            retryable=True,
                        )
                    ],
                ),
                artifacts=[],
            )

        result = output.result
        snapshot = SnapshotEvent(
            id=job.snapshot_id,
            case_id=job.case_id,
            status=result.status,
            started_at=result.started_at,
            finished_at=result.finished_at,
            results=[result],
            occurred_at=result.finished_at,
        )
        try:
            self.case_service.record_snapshot(snapshot, output.artifacts)
        except Exception:
            self._update(
                job_id,
                status=CollectorStatus.FAILED,
                finished_at=datetime.now(UTC),
                error="The collection result could not be persisted.",
            )
            return
        self._update(
            job_id,
            status=result.status,
            finished_at=result.finished_at,
            error=result.errors[0].message if result.status == CollectorStatus.FAILED else None,
        )

    def _update(self, job_id: str, **updates) -> None:  # type: ignore[no-untyped-def]
        with self._lock:
            self._jobs[job_id] = self._jobs[job_id].model_copy(update=updates)

    def get(self, job_id: str) -> CollectionJobView:
        with self._lock:
            return self._jobs[job_id].model_copy(deep=True)

    def latest_for_case(self, case_id: str) -> CollectionJobView | None:
        with self._lock:
            matching = [job for job in self._jobs.values() if job.case_id == case_id]
            if not matching:
                return None
            return max(matching, key=lambda item: item.queued_at).model_copy(deep=True)

    def wait(self, job_id: str, timeout: float = 10) -> CollectionJobView:
        with self._lock:
            future = self._futures[job_id]
        future.result(timeout=timeout)
        return self.get(job_id)
