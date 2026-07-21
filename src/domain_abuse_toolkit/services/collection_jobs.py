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
from domain_abuse_toolkit.services.collectors import CollectorBatchOutput, CollectorOutput
from domain_abuse_toolkit.services.evidence import PendingArtifact


class PassiveCollector(Protocol):
    version: str

    def collect(self, target: NormalizedTarget, snapshot_id: str) -> CollectorOutput: ...


class PassiveWebCollector(Protocol):
    version: str

    def collect(
        self, target: NormalizedTarget, snapshot_id: str
    ) -> CollectorBatchOutput: ...


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
        web_collector: PassiveWebCollector | None = None,
        rdap_collector: PassiveCollector | None = None,
        *,
        max_workers: int = 2,
        max_pending_jobs: int = 10,
    ) -> None:
        self.case_service = case_service
        self.dns_collector = dns_collector
        self.web_collector = web_collector
        self.rdap_collector = rdap_collector
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="dat-collector"
        )
        self._lock = threading.Lock()
        self._max_pending_jobs = max_pending_jobs
        self._jobs: dict[str, CollectionJobView] = {}
        self._futures: dict[str, Future[None]] = {}

    def start_dns(self, case_id: str) -> CollectionJobView:
        return self._start(case_id, self._run_dns)

    def start_passive(self, case_id: str) -> CollectionJobView:
        if self.web_collector is None:
            raise ValueError("The HTTP/TLS collector is not configured.")
        return self._start(case_id, self._run_passive)

    def _start(self, case_id: str, worker) -> CollectionJobView:  # type: ignore[no-untyped-def]
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
            future = self._executor.submit(worker, job.id, record.target.model_copy(deep=True))
            self._futures[job.id] = future
            return job.model_copy(deep=True)

    def _run_dns(self, job_id: str, target: NormalizedTarget) -> None:
        self._update(job_id, status=CollectorStatus.RUNNING, started_at=datetime.now(UTC))
        job = self.get(job_id)
        try:
            output = self.dns_collector.collect(target, job.snapshot_id)
        except Exception:  # collector boundary deliberately hides target-controlled details
            output = CollectorOutput(
                result=self._failed_result(
                    "dns",
                    self.dns_collector.version,
                    job.started_at,
                    "The DNS collector stopped unexpectedly.",
                ),
                artifacts=[],
            )
        self._persist(job_id, [output.result], output.artifacts)

    def _run_passive(self, job_id: str, target: NormalizedTarget) -> None:
        self._update(job_id, status=CollectorStatus.RUNNING, started_at=datetime.now(UTC))
        job = self.get(job_id)
        try:
            dns_output = self.dns_collector.collect(target, job.snapshot_id)
        except Exception:  # collector boundary deliberately hides target-controlled details
            dns_output = CollectorOutput(
                result=self._failed_result(
                    "dns",
                    self.dns_collector.version,
                    job.started_at,
                    "The DNS collector stopped unexpectedly.",
                ),
                artifacts=[],
            )

        results = [dns_output.result]
        artifacts = list(dns_output.artifacts)
        if dns_output.result.status == CollectorStatus.FAILED:
            now = datetime.now(UTC)
            for collector in ("http", "tls"):
                results.append(
                    CollectorResult(
                        collector=collector,
                        version=self.web_collector.version if self.web_collector else "1.0",
                        status=CollectorStatus.SKIPPED,
                        started_at=now,
                        finished_at=now,
                        errors=[
                            CollectorError(
                                code="dns_safety_gate_failed",
                                message=(
                                    "The connection-based collector was skipped because "
                                    "the DNS safety gate failed."
                                ),
                            )
                        ],
                    )
                )
        else:
            try:
                assert self.web_collector is not None
                web_output = self.web_collector.collect(target, job.snapshot_id)
            except Exception:  # collector boundary deliberately hides target-controlled details
                web_output = CollectorBatchOutput(
                    results=[
                        self._failed_result(
                            "http",
                            self.web_collector.version if self.web_collector else "1.0",
                            job.started_at,
                            "The HTTP/TLS collector stopped unexpectedly.",
                        ),
                        self._failed_result(
                            "tls",
                            self.web_collector.version if self.web_collector else "1.0",
                            job.started_at,
                            "The HTTP/TLS collector stopped unexpectedly.",
                        ),
                    ],
                    artifacts=[],
                )
            results.extend(web_output.results)
            artifacts.extend(web_output.artifacts)

        if self.rdap_collector is not None:
            try:
                rdap_output = self.rdap_collector.collect(target, job.snapshot_id)
            except Exception:  # collector boundary deliberately hides endpoint details
                rdap_output = CollectorOutput(
                    result=self._failed_result(
                        "rdap",
                        self.rdap_collector.version,
                        job.started_at,
                        "The RDAP collector stopped unexpectedly.",
                    ),
                    artifacts=[],
                )
            results.append(rdap_output.result)
            artifacts.extend(rdap_output.artifacts)
        self._persist(job_id, results, artifacts)

    def _persist(
        self,
        job_id: str,
        results: list[CollectorResult],
        artifacts: list[PendingArtifact],
    ) -> None:
        job = self.get(job_id)
        started_at = min(result.started_at for result in results)
        finished_at = max(result.finished_at for result in results)
        status = self._snapshot_status(results)
        snapshot = SnapshotEvent(
            id=job.snapshot_id,
            case_id=job.case_id,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            results=results,
            occurred_at=finished_at,
        )
        try:
            self.case_service.record_snapshot(snapshot, artifacts)
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
            status=status,
            finished_at=finished_at,
            error=next(
                (
                    error.message
                    for result in results
                    if result.status == CollectorStatus.FAILED
                    for error in result.errors
                ),
                None,
            ),
        )

    @staticmethod
    def _snapshot_status(results: list[CollectorResult]) -> CollectorStatus:
        active = [result.status for result in results if result.status != CollectorStatus.SKIPPED]
        if active and all(status == CollectorStatus.COMPLETE for status in active):
            return CollectorStatus.COMPLETE
        if active and all(status == CollectorStatus.FAILED for status in active):
            return CollectorStatus.FAILED
        return CollectorStatus.PARTIAL

    @staticmethod
    def _failed_result(
        collector: str,
        version: str,
        started_at: datetime | None,
        message: str,
    ) -> CollectorResult:
        now = datetime.now(UTC)
        return CollectorResult(
            collector=collector,
            version=version,
            status=CollectorStatus.FAILED,
            started_at=started_at or now,
            finished_at=now,
            errors=[
                CollectorError(
                    code="collector_failure",
                    message=message,
                    retryable=True,
                )
            ],
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
