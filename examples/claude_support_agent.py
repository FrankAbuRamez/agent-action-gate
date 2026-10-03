"""A Claude support agent whose tools all go through the Agent Action Gate.

Claude can look up orders on its own. Refunds and emails are queued for a human
approver; anything outside policy is refused with the reason, which Claude
relays to the customer instead of retrying.

    pip install anthropic
    export ANTHROPIC_API_KEY=...
    python -m examples.claude_support_agent
"""
import json

import anthropic
from anthropic import beta_tool

from gate import ALLOW, NEEDS_APPROVAL, load_gate

gate = load_gate("policy.example.json", "audit.log.jsonl", "KILL_SWITCH")
ORDERS = {"A-1001": {"item": "Space heater", "paid": 129.0, "status": "delivered damaged"}}


def gated(action: str, params: dict, run) -> str:
    intent = {"action": action, "params": params, "agent": "support-bot"}
    decision = gate.evaluate(intent)
    if decision.status == ALLOW:
        return json.dumps(gate.execute(intent, run))
    if decision.status == NEEDS_APPROVAL:
        return (f"Queued for human approval as {decision.request_id}. "
                "Tell the customer a team member will confirm shortly. Do not retry.")
    return "Refused by policy: " + "; ".join(decision.reasons) + ". Explain this to the customer. Do not retry."


@beta_tool
def lookup_order(order_id: str) -> str:
    """Look up an order's item, amount paid and delivery status.

    Args:
        order_id: Order number, for example A-1001.
    """
    return gated("lookup_order", {"order": order_id}, lambda p: ORDERS.get(p["order"], "not found"))


@beta_tool
def issue_refund(order_id: str, amount: float) -> str:
    """Request a refund for an order. Refunds need human approval.

    Args:
        order_id: Order number.
        amount: Refund amount in dollars.
    """
    return gated("issue_refund", {"order": order_id, "amount": amount}, lambda p: "refund issued")


@beta_tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a customer. Emails need human approval.

    Args:
        to: Recipient email address.
        subject: Subject line.
        body: Plain-text body.
    """
    return gated("send_email", {"to": [to], "subject": subject, "body": body}, lambda p: "sent")


def main() -> None:
    client = anthropic.Anthropic()
    runner = client.beta.messages.tool_runner(
        model="claude-opus-5-5",
        max_tokens=16000,
        system="You are a customer support agent. Use tools for every action; never claim an action happened unless a tool confirmed it.",
        tools=[lookup_order, issue_refund, send_email],
        messages=[{"role": "user", "content": "My heater from order A-1001 arrived broken. Please refund me in full and email jo@customer.example.org."}],
    )
    for message in runner:
        if message.stop_reason == "refusal":
            print("Claude declined; route to a human.")
            break
        for block in message.content:
            if block.type == "text":
                print(block.text)
    print("\nPending approvals:", [r for r, a in gate.pending.items() if not a.token])


if __name__ == "__main__":
    main()
