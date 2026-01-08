# Cursor Workflow Guide

This guide explains how to use Cursor to incrementally refine the STIG generator scripts.

## Prerequisites

- `.cursorrules` is set up as the project's "source of truth"
- `REFACTORING_SUMMARY.md` documents the architecture
- Example outputs are in `examples/rhel9/` for style reference
- STIG files are organized in `data/stigs/`

## Step-by-Step Refinement

### 1. Implement `parse_stig.py` with Real Parsing

**Open**: `scripts/parse_stig.py`

**Tell Cursor**:
```
Use the project rules in .cursorrules and the summary in REFACTORING_SUMMARY.md.

Goal:
- Implement parse_xccdf_file() so it:
  - Calls app.parsers.xccdf_parser.parse_xccdf(xccdf_path)
  - Maps the resulting objects into a list[StigControl]-style dicts with:
    sv_id, nist_id, severity, title, description, check_text, fix_text, product, category, automation_level="tbd"

- Wire up a CLI so I can run:
  python scripts/parse_stig.py --xccdf <path> --output <json_path>

Leave save_controls_to_json and load_controls_from_json as they are, but make sure they work with the new data structure.
```

**Test**:
```bash
python scripts/parse_stig.py \
  --xccdf stigs/input/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml \
  --output data/json/rhel9_test_controls.json
```

---

### 2. Implement Category-Specific Hardening Tasks

**Open**: `scripts/generate_hardening.py`

**Tell Cursor**:
```
Using the project rules and the JSON structure produced by parse_stig.py, implement the TODOs here:

- Improve categorize_control() to infer categories from:
  - title, check_text, fix_text
  - patterns like "mount | grep", "dnf list --installed", "systemctl is-active", "grep -i" on /etc/sysconfig, /etc/ssh, etc.

- Implement:
  - generate_file_permission_tasks()
  - generate_package_present_tasks()
  - generate_package_absent_tasks()
  - generate_service_enabled_tasks()
  - generate_service_disabled_tasks()
  - generate_sysctl_tasks()
  - generate_mount_option_tasks()
  - generate_ssh_config_tasks()
  - generate_firewalld_tasks()

- Each function should return valid Ansible task dicts using proper modules, not shell, whenever possible.

Make sure:
- Every control in the JSON yields at least one hardening task.
- Tasks are tagged with their STIG ID.
- tests/test_coverage.py continues to pass.
```

**Test**:
```bash
python scripts/generate_hardening.py \
  --input data/json/rhel9_test_controls.json \
  --output ansible/stig_rhel9_test_hardening.yml \
  --product rhel9 \
  --verify-coverage
```

---

### 3. Make Checker Tasks Smarter

**Open**: `scripts/generate_checker.py`

**Tell Cursor**:
```
Refine generate_checker_task() so it creates category-specific checker tasks, using modules instead of raw shell where possible.

Use categorize_control() from generate_hardening.py for alignment, and implement branches like:

- For package_present: use package_facts or dnf query via command + failed_when.
- For service_enabled/active: use service_facts or systemctl via command + failed_when.
- For mount checks: use 'command: mount' + 'register' + asserts on stdout.
- For file permissions/ownership: use stat module, assert on mode/owner/group.

Do NOT copy the original English "Must: ..." texts into tasks. Use concise comments and logic that matches the check_text semantics.

Ensure every StigControl produces at least one checker task and keep tests/test_coverage.py passing.
```

**Test**:
```bash
python scripts/generate_checker.py \
  --input data/json/rhel9_test_controls.json \
  --output ansible/stig_rhel9_test_checker.yml \
  --product rhel9 \
  --verify-coverage
```

---

### 4. Clean Up and Enrich CTP Generation

**Open**: `scripts/generate_ctp.py`

**Tell Cursor**:
```
Refine generate_ctp_rows_for_control() to create 1–3 high-quality steps per StigControl using real commands derived from check_text and fix_text.

Rules:
- Action/Command: human-readable CLI instructions, e.g.:
  'Run: mount | grep /var/log'
- Expected Output/Result: describe the condition being verified, e.g.:
  '"/var/log" is mounted on a separate filesystem with the nodev,noexec,nosuid options.'
- Expected Screen Output (what user sees): show a typical command output snippet or overall description.
- Notes: list NIST ID, relevant file paths, special approvals (ISSO, etc.).

Strip boilerplate phrases like "Must:", "If it is not, this is a finding." from the generated text. That policy language belongs to STIG docs, not the test steps.

Also implement format_nist_control_id() so NIST IDs are consistently shaped like "AU.02.b" etc.

Use the style in examples/rhel9/stig_rhel9_ctp_example.csv as a reference for tone and structure, but improve clarity and remove awkward "Must:" and "If it does not, this is a finding." language.

Keep:
- One or more rows per sv_id.
- CSV columns exactly as defined.
- Coverage tests passing.
```

**Test**:
```bash
python scripts/generate_ctp.py \
  --input data/json/rhel9_test_controls.json \
  --output ctp/stig_rhel9_test_ctp.csv \
  --verify-coverage
```

---

## Running Coverage Tests

After each major change, run:

```bash
pytest tests/test_coverage.py \
  --json-path data/json/rhel9_test_controls.json \
  --hardening-path ansible/stig_rhel9_test_hardening.yml \
  --checker-path ansible/stig_rhel9_test_checker.yml \
  --ctp-path ctp/stig_rhel9_test_ctp.csv
```

Or use the test functions directly:

```python
from tests.test_coverage import verify_hardening_coverage, verify_checker_coverage, verify_ctp_coverage

# Verify each artifact
verify_hardening_coverage(json_path, hardening_path)
verify_checker_coverage(json_path, checker_path)
verify_ctp_coverage(json_path, ctp_path)
```

## Iteration Pattern

1. **Make a small change** to one generator
2. **Test locally** with a small STIG subset
3. **Run coverage tests** to ensure nothing broke
4. **Commit** when tests pass
5. **Repeat** for the next category or improvement

## Tips

- **Start small**: Get one category working perfectly before moving to the next
- **Reference examples**: Always point Cursor to `examples/rhel9/` for style
- **Test incrementally**: Don't wait until everything is done to test
- **Use existing code**: Leverage `app.generators.extractors` and `app.parsers.xccdf_parser`
- **Keep it simple**: Prefer small, composable functions over complex logic

## Common Issues

### Coverage Test Fails

- Check that every STIG ID has at least one task/row
- Verify tags are correctly formatted in playbooks
- Ensure CSV has the exact header format

### Generated Tasks Are Too Generic

- Improve category detection in `categorize_control()`
- Extract more specific values from `check_text` and `fix_text`
- Use the extractors from `app.generators.extractors`

### CTP Language Is Awkward

- Reference `examples/rhel9/stig_rhel9_ctp_example.csv`
- Strip policy language ("Must:", "If it does not, this is a finding.")
- Focus on clear, actionable instructions




