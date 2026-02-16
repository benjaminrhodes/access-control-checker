"""Tests for least-privilege analyzer."""

import pytest
from src.policy import Policy, Statement, parse_policy
from src.analyzer import analyze_policy, Violation, ViolationType


def test_detect_wildcard_action():
    """Test detection of wildcard actions like s3:* or *."""
    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": ["s3:*"],
                "Resource": "arn:aws:s3:::bucket/*",
            },
        }
    )
    violations = analyze_policy(policy)
    assert len(violations) == 1
    assert violations[0].type == ViolationType.WILDCARD_ACTION


def test_detect_wildcard_action_generic():
    """Test detection of generic wildcard *."""
    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": ["*"], "Resource": "*"},
        }
    )
    violations = analyze_policy(policy)
    assert len(violations) >= 1
    assert any(v.type == ViolationType.WILDCARD_ACTION for v in violations)


def test_detect_wildcard_resource():
    """Test detection of wildcard resources."""
    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
        }
    )
    violations = analyze_policy(policy)
    assert len(violations) == 1
    assert violations[0].type == ViolationType.WILDCARD_RESOURCE


def test_detect_iam_wildcard():
    """Test detection of overly broad IAM permissions."""
    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"},
        }
    )
    violations = analyze_policy(policy)
    violation_types = [v.type for v in violations]
    assert ViolationType.WILDCARD_ACTION in violation_types


def test_no_violations_for_specific_permissions():
    """Test that specific permissions don't trigger violations."""
    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::specific-bucket/specific-key",
            },
        }
    )
    violations = analyze_policy(policy)
    assert len(violations) == 0


def test_multiple_statements_with_violations():
    """Test analyzing multiple statements."""
    policy = parse_policy(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::bucket/*",
                },
                {"Effect": "Allow", "Action": ["ec2:*"], "Resource": "*"},
            ],
        }
    )
    violations = analyze_policy(policy)
    assert len(violations) == 2
    assert violations[0].type == ViolationType.WILDCARD_ACTION


def test_deny_statements_ignored():
    """Test that Deny statements are not checked for violations."""
    policy = parse_policy(
        {"Version": "2012-10-17", "Statement": {"Effect": "Deny", "Action": ["*"], "Resource": "*"}}
    )
    violations = analyze_policy(policy)
    assert len(violations) == 0
