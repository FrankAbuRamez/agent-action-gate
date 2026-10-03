"""Fail-closed approval gate for actions proposed by AI agents.

Every proposed action ("intent") is checked against a policy before anything
runs. Low-risk actions pass, risky ones wait for a named human approver, and
anything unknown or out of limits is denied. Every decision is written to a
hash-chained audit log, so edits to history are detectable.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

ALLOW, NEEDS_APPROVAL, DENY = "ALLOW", "NEEDS_APPROVAL", "DENY"
GENESIS = "0" * 64


def canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def intent_hash(intent: dict) -> str:
    return hashlib.sha256(canonical(intent).encode()).hexdigest()


@dataclass
class Decision:
    status: str
    reasons: list[str]
    intent_hash: str
    request_id: str | None = None


@dataclass
class Approval:
    request_id: str
    intent_hash: str
    approver: str | None = None
    token: str | None = None
    expires_at: float = 0.0
    used: bool = False


@dataclass
class Gate:
    policy: dict
    log_path: Path
    kill_switch_path: Path
    clock: Callable[[], float] = time.time
    approval_ttl_s: int = 900
    pending: dict[str, Approval] = field(default_factory=dict)
    spend: dict[str, float] = field(default_factory=dict)

    # ---------- evaluation ----------
    def evaluate(self, intent: dict) -> Decision:
        h = intent_hash(intent)
        reasons = self._violations(intent)
        if reasons:
            decision = Decision(DENY, reasons, h)
        elif self._rule(intent)["tier"] == "allow":
            decision = Decision(ALLOW, ["low-risk action allowed by policy"], h)
        else:
            request_id = f"R-{secrets.token_hex(4)}"
            self.pending[request_id] = Approval(request_id, h)
            decision = Decision(NEEDS_APPROVAL, ["policy requires a human approver"], h, request_id)
        self._log("evaluate", intent=intent, decision=decision.__dict__)
        return decision

    def _rule(self, intent: dict) -> dict:
        return self.policy["actions"].get(intent.get("action"), {"tier": self.policy.get("default_tier", "deny")})

    def _violations(self, intent: dict) -> list[str]:
        if self.kill_switch_path.exists():
            return ["kill switch is on: all agent actions are blocked"]
        if intent.get("action") not in self.policy["actions"]:
            return [f"action '{intent.get('action')}' is not in the policy (default deny)"]
        rule = self._rule(intent)
        if rule["tier"] == "deny":
            return [f"action '{intent['action']}' is never allowed for agents"]
        params = intent.get("params", {})
        problems = []
        domains = rule.get("allowed_domains")
        if domains:
            for address in _as_list(params.get("to")):
                if address.rsplit("@", 1)[-1].lower() not in domains:
                    problems.append(f"recipient {address} is outside allowed domains")
        amount = params.get("amount")
        if "max_amount" in rule:
            if not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount <= 0:
                problems.append("amount must be a positive number")
            else:
                if amount > rule["max_amount"]:
                    problems.append(f"amount {amount} exceeds per-action limit {rule['max_amount']}")
                spent = self.spend.get(self._day_key(intent["action"]), 0.0)
                if spent + amount > rule.get("daily_limit", float("inf")):
                    problems.append(f"daily limit {rule['daily_limit']} would be exceeded ({spent} already used)")
        return problems

    # ---------- approval and execution ----------
    def approve(self, request_id: str, approver: str) -> str:
        approval = self.pending.get(request_id)
        if approval is None:
            raise PermissionError(f"unknown request {request_id}")
        if not approver.strip():
            raise PermissionError("approver name is required")
        approval.approver = approver
        approval.token = secrets.token_urlsafe(16)
        approval.expires_at = self.clock() + self.approval_ttl_s
        self._log("approve", request_id=request_id, approver=approver, intent_hash=approval.intent_hash)
        return approval.token

    def execute(self, intent: dict, run: Callable[[dict], Any], token: str | None = None) -> Any:
        decision_reasons = self._violations(intent)  # re-check: limits or kill switch may have changed
        if decision_reasons:
            self._log("blocked", intent=intent, reasons=decision_reasons)
            raise PermissionError("; ".join(decision_reasons))
        if self._rule(intent)["tier"] == "approve":
            self._consume_token(intent, token)
        result = run(intent.get("params", {}))
        amount = intent.get("params", {}).get("amount")
        if isinstance(amount, (int, float)) and "max_amount" in self._rule(intent):
            key = self._day_key(intent["action"])
            self.spend[key] = self.spend.get(key, 0.0) + amount
        self._log("executed", intent=intent, result=str(result)[:200])
        return result

    def _consume_token(self, intent: dict, token: str | None) -> None:
        h = intent_hash(intent)
        match = next((a for a in self.pending.values() if a.token and a.token == token), None)
        problem = None
        if match is None:
            problem = "no valid approval token"
        elif match.used:
            problem = "approval token already used"
        elif match.intent_hash != h:
            problem = "approval was for a different action (parameters changed after approval)"
        elif self.clock() > match.expires_at:
            problem = "approval expired"
        if problem:
            self._log("blocked", intent=intent, reasons=[problem])
            raise PermissionError(problem)
        match.used = True

    def _day_key(self, action: str) -> str:
        return f"{action}:{time.strftime('%Y-%m-%d', time.gmtime(self.clock()))}"

    # ---------- audit log ----------
    def _log(self, event: str, **data: Any) -> None:
        prev = _last_hash(self.log_path)
        entry = {"ts": round(self.clock(), 3), "event": event, **data, "prev_hash": prev}
        entry["hash"] = hashlib.sha256((prev + canonical(entry)).encode()).hexdigest()
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(canonical(entry) + "\n")


def verify_log(path: Path) -> tuple[bool, str]:
    prev = GENESIS
    if not path.exists():
        return True, "empty log"
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        entry = json.loads(line)
        claimed = entry.pop("hash")
        if entry["prev_hash"] != prev:
            return False, f"line {n}: chain broken (entry removed or reordered)"
        if hashlib.sha256((prev + canonical(entry)).encode()).hexdigest() != claimed:
            return False, f"line {n}: contents changed after it was written"
        prev = claimed
    return True, f"{n} entries verified"


def _last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS
    last = path.read_text(encoding="utf-8").splitlines()[-1]
    return json.loads(last)["hash"]


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def load_gate(policy_path: str | Path, log_path: str | Path, kill_switch_path: str | Path) -> Gate:
    policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))
    return Gate(policy, Path(log_path), Path(kill_switch_path))
