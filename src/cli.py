"""CLI interface for access-control-checker."""

import sys
import json
from src.policy import parse_policy
from src.analyzer import analyze_policy


def analyze_file(filepath: str) -> int:
    """Analyze a policy file and return exit code."""
    try:
        if filepath == "-":
            policy_dict = json.load(sys.stdin)
        else:
            with open(filepath) as f:
                policy_dict = json.load(f)

        policy = parse_policy(policy_dict)
        violations = analyze_policy(policy)

        if not violations:
            print("Policy passes least-privilege checks.")
            return 0

        print(f"Found {len(violations)} violation(s):")
        for v in violations:
            print(f"  - [{v.type.value}] {v.message}")

        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON - {e}")
        return 1
    except FileNotFoundError:
        print(f"Error: File not found - {filepath}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def main(args=None):
    """Main entry point."""
    if args is None:
        args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print("Usage: access-control-checker <policy.json>")
        print("  or: cat policy.json | access-control-checker -")
        print("\nAnalyze IAM policies for least-privilege violations.")
        return 0 if args and args[0] in ("-h", "--help") else 1

    return analyze_file(args[0])


if __name__ == "__main__":
    sys.exit(main())
