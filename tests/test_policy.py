"""Tests for IAM policy parser."""

import pytest
from src.policy import Policy, Statement, parse_policy


def test_parse_policy_with_single_statement():
    """Test parsing a policy with a single statement."""
    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }
    policy = parse_policy(policy_json)
    assert len(policy.statements) == 1
    stmt = policy.statements[0]
    assert stmt.effect == "Allow"
    assert stmt.actions == ["s3:GetObject"]
    assert stmt.resources == ["arn:aws:s3:::example-bucket/*"]


def test_parse_policy_with_multiple_statements():
    """Test parsing a policy with multiple statements."""
    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"},
            {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": "arn:aws:s3:::bucket/*"},
        ],
    }
    policy = parse_policy(policy_json)
    assert len(policy.statements) == 2
    assert policy.statements[0].effect == "Allow"
    assert policy.statements[1].effect == "Deny"


def test_parse_policy_single_statement_not_list():
    """Test parsing a policy where Statement is a single object (not list)."""
    policy_json = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": ["ec2:*"], "Resource": "*"},
    }
    policy = parse_policy(policy_json)
    assert len(policy.statements) == 1


def test_statement_is_list_of_actions():
    """Test that Action can be a single string or list."""
    policy_json = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
    }
    policy = parse_policy(policy_json)
    assert policy.statements[0].actions == ["s3:GetObject"]


def test_statement_is_list_of_resources():
    """Test that Resource can be a single string or list."""
    policy_json = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::bucket/*",
        },
    }
    policy = parse_policy(policy_json)
    assert policy.statements[0].resources == ["arn:aws:s3:::bucket/*"]
