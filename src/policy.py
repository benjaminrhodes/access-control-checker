"""IAM policy parsing and analysis."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Statement:
    """Represents a policy statement."""

    effect: str
    actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    sid: str = ""


@dataclass
class Policy:
    """Represents an IAM policy."""

    version: str = ""
    statements: list[Statement] = field(default_factory=list)


def parse_policy(policy_dict: dict[str, Any]) -> Policy:
    """Parse a policy dictionary into a Policy object."""
    policy = Policy()
    policy.version = policy_dict.get("Version", "")

    statement_data = policy_dict.get("Statement", [])

    # Handle single statement (dict) vs list
    if isinstance(statement_data, dict):
        statement_data = [statement_data]

    for stmt_dict in statement_data:
        actions = stmt_dict.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = stmt_dict.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        statement = Statement(
            effect=stmt_dict.get("Effect", "Allow"),
            actions=actions,
            resources=resources,
            sid=stmt_dict.get("Sid", ""),
        )
        policy.statements.append(statement)

    return policy
