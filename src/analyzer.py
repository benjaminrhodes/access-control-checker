"""IAM policy least-privilege analyzer."""

from enum import Enum
from dataclasses import dataclass
from src.policy import Policy


class ViolationType(Enum):
    """Types of least-privilege violations."""

    WILDCARD_ACTION = "wildcard_action"
    WILDCARD_RESOURCE = "wildcard_resource"
    OVERLY_BROAD_SERVICE = "overly_broad_service"


@dataclass
class Violation:
    """Represents a policy violation."""

    type: ViolationType
    message: str
    statement_index: int


def analyze_policy(policy: Policy) -> list[Violation]:
    """Analyze a policy for least-privilege violations."""
    violations = []

    for idx, statement in enumerate(policy.statements):
        # Skip Deny statements - they are typically used to restrict
        if statement.effect != "Allow":
            continue

        # Check for wildcard actions
        for action in statement.actions:
            if "*" in action:
                violations.append(
                    Violation(
                        type=ViolationType.WILDCARD_ACTION,
                        message=f"Action '{action}' uses wildcard",
                        statement_index=idx,
                    )
                )

        # Check for wildcard resources
        for resource in statement.resources:
            if resource == "*":
                violations.append(
                    Violation(
                        type=ViolationType.WILDCARD_RESOURCE,
                        message="Resource '*' is overly broad",
                        statement_index=idx,
                    )
                )

    return violations
