"""
Research Task Manager and Evidence Management for Bug Bounty Workflows.

Tracks bug bounty research tasks mapped to official program policies.
Maintains granular status lifecycles, evidence completeness auditing, duplicate
detection reviews, and report readiness gates.
Enforces human-controlled status transitions (never auto-submits or auto-accepts).
Redacts secrets, credentials, and personal data (PII).
"""

import os
import json
import uuid
import datetime
from typing import Dict, List, Optional, Tuple, Any

from appsec_assistant.models import (
    ResearchStatus,
    ResearchTask,
    VulnerabilityFinding,
    ProgramPolicy,
    ConfidenceLevel,
    SeverityLevel,
    sanitize_evidence_text,
)
from appsec_assistant.policy import (
    ProgramPolicyManager,
    UnauthorizedTargetError,
    PolicyStaleError,
)


class ResearchError(Exception):
    """Base exception for research manager errors."""
    pass


class TaskNotFoundError(ResearchError):
    """Raised when a research task ID cannot be found."""
    pass


class ReportReadinessError(ResearchError):
    """Raised when an action requires report readiness but blockers exist."""
    pass


class HumanConfirmationRequiredError(ResearchError):
    """Raised when a status transition requires explicit human confirmation."""
    pass


class ResearchManager:
    """
    Manages bug bounty research tasks, findings evidence, status transitions,
    and submission tracking.
    """

    def __init__(
        self,
        policy_manager: ProgramPolicyManager,
        storage_path: Optional[str] = None,
    ):
        self.policy_manager = policy_manager
        self.storage_path = storage_path
        self._tasks: Dict[str, ResearchTask] = {}
        self._findings: Dict[str, VulnerabilityFinding] = {}

        if self.storage_path and os.path.exists(self.storage_path):
            self.load_from_file(self.storage_path)

    def calculate_evidence_completeness(
        self,
        finding: VulnerabilityFinding,
        policy: Optional[ProgramPolicy] = None,
    ) -> Tuple[float, List[str]]:
        """
        Calculates an evidence completeness score (0.0 to 1.0) and identifies missing components.
        Evaluates affected asset, reproduction steps, request/response evidence,
        impact rationale, and remediation.
        """
        missing_items: List[str] = []
        score = 0.0

        # 1. Affected Asset specified (+0.20)
        target_asset = finding.affected_authorized_asset or finding.target_url
        if target_asset and target_asset.strip():
            score += 0.20
        else:
            missing_items.append("Missing affected target asset")

        # 2. Reproduction Steps (+0.20)
        is_generic_placeholder = any(
            "Verify whether the expected security control or header is absent" in step
            for step in (finding.reproduction_steps or [])
        )
        if finding.reproduction_steps and len(finding.reproduction_steps) >= 2 and not is_generic_placeholder:
            score += 0.20
        else:
            missing_items.append("Incomplete reproduction steps (specific manual verification steps required)")

        # 3. Minimal Request / Response Evidence (+0.20)
        has_evidence = bool(
            (finding.minimal_request_evidence and finding.minimal_request_evidence.strip())
            or (finding.minimal_response_evidence and finding.minimal_response_evidence.strip())
            or (finding.evidence and len(finding.evidence.strip()) > 10)
        )
        if has_evidence:
            score += 0.20
        else:
            missing_items.append("Missing minimal HTTP request/response evidence")

        # 4. Realistic Impact (+0.20)
        if finding.impact and len(finding.impact.strip()) >= 15:
            score += 0.20
        else:
            missing_items.append("Missing detailed impact analysis")

        # 5. Severity / Priority Rationale (+0.10)
        if finding.priority_rationale and finding.priority_rationale.strip():
            score += 0.10
        else:
            missing_items.append("Missing severity justification")

        # 6. Remediation Guidance (+0.10)
        if finding.remediation and len(finding.remediation.strip()) >= 10:
            score += 0.10
        else:
            missing_items.append("Missing remediation recommendation")

        # If policy specifies required evidence, check those as well
        if policy and policy.required_evidence:
            for req in policy.required_evidence:
                req_lower = req.lower()
                if "request" in req_lower and not finding.minimal_request_evidence and not finding.evidence:
                    if "Missing policy-required request evidence" not in missing_items:
                        missing_items.append("Missing policy-required request evidence")
                if "response" in req_lower and not finding.minimal_response_evidence and not finding.evidence:
                    if "Missing policy-required response evidence" not in missing_items:
                        missing_items.append("Missing policy-required response evidence")

        final_score = round(min(1.0, score), 2)
        return final_score, missing_items

    def check_report_readiness(self, task_id: str) -> Tuple[bool, List[str]]:
        """
        Audits whether a research task is ready for review or export.
        Verifies scope validity, exclusion absence, policy freshness, and evidence completeness.
        Fails closed on missing evidence or out-of-scope assets.
        """
        task = self.get_task(task_id)
        if not task:
            raise TaskNotFoundError(f"Task '{task_id}' not found.")

        finding = self.get_finding_for_task(task_id)
        policy = self.policy_manager.get_policy(task.program_id)

        blockers: List[str] = []

        if not policy:
            blockers.append(f"Associated program policy '{task.program_id}' does not exist.")
        else:
            if not policy.is_verified:
                blockers.append(f"Program policy '{policy.program_id}' has not been verified by a researcher.")
            if policy.is_stale():
                blockers.append(f"Program policy '{policy.program_id}' scope verification is stale or expired.")

            # Validate affected asset against policy scope
            target_asset = task.affected_asset or (finding.target_url if finding else "")
            if not target_asset:
                blockers.append("No affected asset specified for this research task.")
            else:
                # Check for explicit exclusion
                for excl in policy.excluded_assets:
                    from appsec_assistant.policy import _match_asset_pattern
                    if _match_asset_pattern(target_asset, excl):
                        blockers.append(
                            f"Asset '{target_asset}' is EXPLICITLY EXCLUDED by policy (rule: '{excl}'). "
                            "Out-of-scope findings cannot be submitted."
                        )
                        break

                # Check for inclusion
                if not self.policy_manager.is_asset_authorized(target_asset, program_id=policy.program_id):
                    blockers.append(f"Asset '{target_asset}' is not in the explicitly authorized scope of policy.")

        if task.duplicate_suspected:
            blockers.append(f"Unresolved suspected duplicate: {task.duplicate_notes or 'Requires researcher duplicate review'}.")

        if finding:
            score, missing = self.calculate_evidence_completeness(finding, policy)
            task.evidence_completeness_score = score
            if missing:
                blockers.extend([f"Evidence gap: {m}" for m in missing])
            if score < 0.70:
                blockers.append(f"Evidence completeness score ({score:.2f}) is below the required 0.70 threshold.")
        else:
            blockers.append("No finding data associated with task.")

        is_ready = len(blockers) == 0
        task.report_ready = is_ready
        task.report_readiness_notes = "; ".join(blockers) if blockers else "All scope and evidence prerequisites verified."
        self._auto_save()

        return is_ready, blockers

    def create_task_from_finding(
        self,
        program_id: str,
        finding: VulnerabilityFinding,
        researcher_notes: str = "",
        next_verification_step: str = "Perform manual curl reproduction and verify server response.",
    ) -> ResearchTask:
        """
        Creates a new ResearchTask linked to a program and finding.
        Initializes status to NEW_OBSERVATION and calculates initial evidence completeness.
        """
        policy = self.policy_manager.get_policy(program_id)
        if not policy:
            raise ResearchError(f"Program policy '{program_id}' not found.")

        task_id = f"TASK-{uuid.uuid4().hex[:8].upper()}"
        finding.research_task_id = task_id
        if not finding.affected_authorized_asset:
            finding.affected_authorized_asset = finding.target_url

        # Ensure evidence is sanitized
        if finding.evidence:
            finding.sanitized_evidence = sanitize_evidence_text(finding.evidence)
        if finding.minimal_request_evidence:
            finding.minimal_request_evidence = sanitize_evidence_text(finding.minimal_request_evidence)
        if finding.minimal_response_evidence:
            finding.minimal_response_evidence = sanitize_evidence_text(finding.minimal_response_evidence)

        score, missing = self.calculate_evidence_completeness(finding, policy)

        # Pre-set submission destination from policy
        dest = policy.reporting_instructions or policy.policy_url

        task = ResearchTask(
            task_id=task_id,
            program_id=program_id,
            finding_id=finding.finding_id,
            title=finding.title,
            affected_asset=finding.affected_authorized_asset or finding.target_url,
            status=ResearchStatus.NEW_OBSERVATION,
            confidence=finding.confidence,
            severity=finding.severity,
            evidence_completeness_score=score,
            duplicate_suspected=False,
            duplicate_notes="",
            next_manual_verification_step=next_verification_step,
            report_ready=False,
            report_readiness_notes="Initial observation recorded. Awaiting manual verification.",
            researcher_notes=researcher_notes,
            submission_destination=dest,
        )

        self._tasks[task_id] = task
        self._findings[task_id] = finding

        # Check readiness initially to record any blockers
        self.check_report_readiness(task_id)
        self._auto_save()
        return task

    def update_task_status(
        self,
        task_id: str,
        new_status: ResearchStatus,
        notes: str = "",
        user_confirmed: bool = False,
        outcome_reference: Optional[str] = None,
    ) -> ResearchTask:
        """
        Transitions a task to a new ResearchStatus.
        Enforces safety rules:
        - READY_FOR_REVIEW requires check_report_readiness passing.
        - SUBMITTED_BY_RESEARCHER, ACCEPTED, REJECTED, DUPLICATE, RESOLVED require explicit user_confirmed=True.
        """
        task = self.get_task(task_id)
        if not task:
            raise TaskNotFoundError(f"Task '{task_id}' not found.")

        # Human confirmation checks
        submission_or_terminal_states = {
            ResearchStatus.SUBMITTED_BY_RESEARCHER,
            ResearchStatus.ACCEPTED,
            ResearchStatus.REJECTED,
            ResearchStatus.DUPLICATE,
            ResearchStatus.RESOLVED,
        }

        if new_status in submission_or_terminal_states and not user_confirmed:
            raise HumanConfirmationRequiredError(
                f"Transition to status '{new_status.value}' requires explicit human researcher confirmation. "
                "Never record external submissions or outcomes without user verification."
            )

        # Gate for READY_FOR_REVIEW: must pass readiness audit
        if new_status == ResearchStatus.READY_FOR_REVIEW:
            is_ready, blockers = self.check_report_readiness(task_id)
            if not is_ready:
                raise ReportReadinessError(
                    f"Cannot transition task '{task_id}' to READY_FOR_REVIEW. Blockers: {'; '.join(blockers)}"
                )

        task.status = new_status
        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        task.updated_at = now_str

        if notes:
            task.researcher_notes = f"{task.researcher_notes}\n[{now_str}] {notes}".strip()

        if new_status == ResearchStatus.SUBMITTED_BY_RESEARCHER:
            task.submitted_date = now_str
            if outcome_reference:
                task.submission_reference = outcome_reference

        if new_status in {ResearchStatus.ACCEPTED, ResearchStatus.REJECTED, ResearchStatus.DUPLICATE, ResearchStatus.RESOLVED}:
            task.outcome = new_status.value
            task.outcome_date = now_str
            if notes:
                task.outcome_notes = notes

        self._auto_save()
        return task

    def record_submission(
        self,
        task_id: str,
        submission_reference: str,
        submission_destination: str,
        user_confirmed: bool = True,
    ) -> ResearchTask:
        """
        Records human-performed submission of a vulnerability report to the program.
        """
        if not user_confirmed:
            raise HumanConfirmationRequiredError(
                "Recording a submission requires explicit confirmation from the researcher."
            )

        task = self.get_task(task_id)
        if not task:
            raise TaskNotFoundError(f"Task '{task_id}' not found.")

        is_ready, blockers = self.check_report_readiness(task_id)
        if not is_ready:
            raise ReportReadinessError(
                f"Cannot record submission for task '{task_id}' with unresolved blockers: {'; '.join(blockers)}"
            )

        task.submission_destination = submission_destination.strip()
        return self.update_task_status(
            task_id=task_id,
            new_status=ResearchStatus.SUBMITTED_BY_RESEARCHER,
            notes=f"Report submitted via {submission_destination}. Reference: {submission_reference}",
            user_confirmed=True,
            outcome_reference=submission_reference.strip(),
        )

    def record_outcome(
        self,
        task_id: str,
        outcome_status: ResearchStatus,
        notes: str,
        user_confirmed: bool = True,
    ) -> ResearchTask:
        """
        Records the program triage outcome (ACCEPTED, REJECTED, DUPLICATE, RESOLVED).
        """
        if outcome_status not in {ResearchStatus.ACCEPTED, ResearchStatus.REJECTED, ResearchStatus.DUPLICATE, ResearchStatus.RESOLVED}:
            raise ResearchError(f"Status '{outcome_status}' is not a valid program outcome state.")

        return self.update_task_status(
            task_id=task_id,
            new_status=outcome_status,
            notes=notes,
            user_confirmed=user_confirmed,
        )

    def flag_suspected_duplicate(self, task_id: str, duplicate_notes: str) -> ResearchTask:
        """Flags a finding as a suspected duplicate and transitions status."""
        task = self.get_task(task_id)
        if not task:
            raise TaskNotFoundError(f"Task '{task_id}' not found.")

        task.duplicate_suspected = True
        task.duplicate_notes = duplicate_notes.strip()
        task.status = ResearchStatus.DUPLICATE_SUSPECTED
        task.updated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        self.check_report_readiness(task_id)
        self._auto_save()
        return task

    def resolve_duplicate_review(self, task_id: str, is_duplicate: bool, notes: str) -> ResearchTask:
        """Resolves duplicate review with researcher notes."""
        task = self.get_task(task_id)
        if not task:
            raise TaskNotFoundError(f"Task '{task_id}' not found.")

        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        task.updated_at = now_str
        if is_duplicate:
            task.duplicate_suspected = True
            task.duplicate_notes = f"Confirmed duplicate by researcher: {notes}"
            task.status = ResearchStatus.DUPLICATE
        else:
            task.duplicate_suspected = False
            task.duplicate_notes = f"Duplicate cleared by researcher: {notes}"
            task.status = ResearchStatus.NEEDS_VERIFICATION

        self.check_report_readiness(task_id)
        self._auto_save()
        return task

    def get_task(self, task_id: str) -> Optional[ResearchTask]:
        return self._tasks.get(task_id)

    def get_finding_for_task(self, task_id: str) -> Optional[VulnerabilityFinding]:
        return self._findings.get(task_id)

    def list_tasks(self, program_id: Optional[str] = None) -> List[ResearchTask]:
        if program_id:
            return [t for t in self._tasks.values() if t.program_id == program_id]
        return list(self._tasks.values())

    def save_to_file(self, filepath: str) -> None:
        """Persists research tasks and findings to JSON."""
        data = {
            "tasks": {tid: t.to_dict() for tid, t in self._tasks.items()},
            "findings": {tid: f.to_dict() for tid, f in self._findings.items()},
        }
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_from_file(self, filepath: str) -> None:
        """Loads research tasks and findings from JSON."""
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        for tid, tdata in data.get("tasks", {}).items():
            self._tasks[tid] = ResearchTask.from_dict(tdata)

        for tid, fdata in data.get("findings", {}).items():
            # Reconstruct VulnerabilityFinding from dict
            try:
                finding = VulnerabilityFinding(
                    finding_id=fdata["finding_id"],
                    title=fdata["title"],
                    category=fdata["category"],
                    severity=SeverityLevel(fdata["severity"]),
                    target_url=fdata["target_url"],
                    description=fdata["description"],
                    impact=fdata["impact"],
                    evidence=fdata["evidence"],
                    remediation=fdata["remediation"],
                    cwe_id=fdata.get("cwe_id"),
                    owasp_category=fdata.get("owasp_category"),
                    priority_rationale=fdata.get("priority_rationale", ""),
                    confidence=ConfidenceLevel(fdata.get("confidence", "HIGH")),
                    confidence_explanation=fdata.get("confidence_explanation", ""),
                    affected_urls=fdata.get("affected_urls", []),
                    affected_authorized_asset=fdata.get("affected_authorized_asset"),
                    reproduction_steps=fdata.get("reproduction_steps", []),
                    sanitized_evidence=fdata.get("sanitized_evidence", ""),
                    http_method=fdata.get("http_method", "GET"),
                    http_status=fdata.get("http_status"),
                    minimal_request_evidence=fdata.get("minimal_request_evidence", ""),
                    minimal_response_evidence=fdata.get("minimal_response_evidence", ""),
                    research_task_id=fdata.get("research_task_id"),
                    human_reviewed=fdata.get("human_reviewed", False),
                    reviewed_by=fdata.get("reviewed_by"),
                    review_date=fdata.get("review_date"),
                    review_notes=fdata.get("review_notes", ""),
                    references=fdata.get("references", []),
                    timestamp=fdata.get("timestamp", ""),
                    ai_triage=fdata.get("ai_triage"),
                )
                self._findings[tid] = finding
            except Exception:
                pass

    def _auto_save(self) -> None:
        if self.storage_path:
            try:
                self.save_to_file(self.storage_path)
            except Exception:
                pass
