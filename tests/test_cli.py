"""Tests for CLI."""

import json
import pytest
from io import StringIO
from src.cli import main, analyze_file


def test_cli_main_no_args(capsys):
    """Test CLI main with no arguments shows usage."""
    result = main([])
    assert result == 1


def test_cli_analyze_file_not_found():
    """Test CLI with non-existent file."""
    result = main(["nonexistent.json"])
    assert result == 1


def test_cli_analyze_valid_policy(tmp_path):
    """Test CLI with valid policy file."""
    policy = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::bucket/key",
        },
    }
    f = tmp_path / "policy.json"
    f.write_text(json.dumps(policy))
    result = main([str(f)])
    assert result == 0


def test_cli_analyze_policy_with_violations(tmp_path, capsys):
    """Test CLI with policy that has violations."""
    policy = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"},
    }
    f = tmp_path / "policy.json"
    f.write_text(json.dumps(policy))
    result = main([str(f)])
    captured = capsys.readouterr()
    assert "violation" in captured.out.lower() or "wildcard" in captured.out.lower()
    assert result == 1


def test_cli_invalid_json(tmp_path):
    """Test CLI with invalid JSON."""
    f = tmp_path / "invalid.json"
    f.write_text("not valid json")
    result = main([str(f)])
    assert result == 1


def test_cli_stdin_input(tmp_path, monkeypatch):
    """Test CLI with stdin input."""
    policy = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::bucket/key",
        },
    }
    monkeypatch.setattr("sys.stdin", StringIO(json.dumps(policy)))
    result = main(["-"])
    assert result == 0
