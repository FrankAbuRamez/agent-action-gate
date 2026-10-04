import json
import tempfile
import unittest
from pathlib import Path

from gate import ALLOW, DENY, NEEDS_APPROVAL, Gate, verify_log

POLICY = json.loads((Path(__file__).resolve().parent.parent / "policy.example.json").read_text())


class Clock:
    def __init__(self, t=1_790_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def refund(amount, order="A-1001"):
    return {"action": "issue_refund", "params": {"order": order, "amount": amount}, "agent": "support-bot"}


class GateTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.clock = Clock()
        self.gate = Gate(POLICY, self.dir / "audit.jsonl", self.dir / "KILL", clock=self.clock)
        self.ran = []

    def run_action(self, params):
        self.ran.append(params)
        return "done"

    def approved_token(self, intent):
        decision = self.gate.evaluate(intent)
        self.assertEqual(decision.status, NEEDS_APPROVAL)
        return self.gate.approve(decision.request_id, "Ops Lead")

    # --- policy tiers ---
    def test_low_risk_action_is_allowed_and_runs_without_token(self):
        intent = {"action": "lookup_order", "params": {"order": "A-1001"}}
        self.assertEqual(self.gate.evaluate(intent).status, ALLOW)
        self.assertEqual(self.gate.execute(intent, self.run_action), "done")

    def test_unknown_action_is_denied_by_default(self):
        decision = self.gate.evaluate({"action": "wire_money", "params": {}})
        self.assertEqual(decision.status, DENY)
        self.assertIn("default deny", decision.reasons[0])

    def test_never_allowed_action_is_denied(self):
        self.assertEqual(self.gate.evaluate({"action": "delete_records", "params": {}}).status, DENY)

    def test_email_outside_allowed_domains_is_denied(self):
        decision = self.gate.evaluate({"action": "send_email", "params": {"to": ["x@attacker.test"]}})
        self.assertEqual(decision.status, DENY)

    def test_refund_over_limit_is_denied(self):
        self.assertEqual(self.gate.evaluate(refund(250)).status, DENY)

    def test_invalid_amount_is_denied(self):
        self.assertEqual(self.gate.evaluate(refund("200")).status, DENY)
        self.assertEqual(self.gate.evaluate(refund(-5)).status, DENY)

    # --- approval flow ---
    def test_approved_action_runs_once(self):
        intent = refund(120)
        token = self.approved_token(intent)
        self.gate.execute(intent, self.run_action, token)
        with self.assertRaisesRegex(PermissionError, "already used"):
            self.gate.execute(intent, self.run_action, token)
        self.assertEqual(len(self.ran), 1)

    def test_risky_action_without_token_is_blocked(self):
        with self.assertRaisesRegex(PermissionError, "no valid approval token"):
            self.gate.execute(refund(50), self.run_action)

    def test_changing_parameters_after_approval_is_blocked(self):
        token = self.approved_token(refund(20))
        with self.assertRaisesRegex(PermissionError, "different action"):
            self.gate.execute(refund(199), self.run_action, token)
        self.assertEqual(self.ran, [])

    def test_approval_expires(self):
        intent = refund(20)
        token = self.approved_token(intent)
        self.clock.t += 901
        with self.assertRaisesRegex(PermissionError, "expired"):
            self.gate.execute(intent, self.run_action, token)

    def test_daily_limit_counts_executed_spend(self):
        for order in ("A-1", "A-2"):
            intent = refund(200, order)
            self.gate.execute(intent, self.run_action, self.approved_token(intent))
        self.assertEqual(self.gate.evaluate(refund(150, "A-3")).status, DENY)  # 400 + 150 > 500

    def test_kill_switch_blocks_even_approved_actions(self):
        intent = refund(20)
        token = self.approved_token(intent)
        (self.dir / "KILL").write_text("stop")
        with self.assertRaisesRegex(PermissionError, "kill switch"):
            self.gate.execute(intent, self.run_action, token)

    # --- audit log ---
    def test_audit_log_detects_tampering(self):
        intent = refund(20)
        self.gate.execute(intent, self.run_action, self.approved_token(intent))
        log = self.dir / "audit.jsonl"
        self.assertTrue(verify_log(log)[0])
        lines = log.read_text().splitlines()
        lines[1] = lines[1].replace("Ops Lead", "someone else")
        log.write_text("\n".join(lines) + "\n")
        ok, message = verify_log(log)
        self.assertFalse(ok)
        self.assertIn("line 2", message)

    def test_audit_log_detects_deleted_entry(self):
        intent = refund(20)
        self.gate.execute(intent, self.run_action, self.approved_token(intent))
        log = self.dir / "audit.jsonl"
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
        self.assertFalse(verify_log(log)[0])


if __name__ == "__main__":
    unittest.main()
