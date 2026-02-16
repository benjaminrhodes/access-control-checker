# Access Control Policy Checker

Validate IAM policies for least-privilege

## Features

- Parse AWS-style IAM policies (JSON)
- Detect overly broad permissions (wildcard actions like `s3:*`)
- Detect overly broad resources (wildcard `*`)
- CLI interface for analyzing policy files
- Supports stdin input

## Usage

```bash
# Analyze a policy file
python -m src.cli policy.json

# Or use stdin
cat policy.json | python -m src.cli -
```

## Exit Codes

- `0`: Policy passes least-privilege checks
- `1`: Policy has violations or error

## Example

```bash
$ python -m src.cli examples/restrictive.json
Policy passes least-privilege checks.

$ python -m src.cli examples/overly-broad.json
Found 2 violation(s):
  - [wildcard_action] Action 's3:*' uses wildcard
  - [wildcard_resource] Resource '*' is overly broad
```

## Testing

```bash
pytest tests/ -v
```

## Security

- Uses synthetic/test data only
- No real credentials or production systems

## License

MIT
