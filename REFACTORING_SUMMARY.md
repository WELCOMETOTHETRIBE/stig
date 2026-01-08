# STIG Generator Refactoring - Summary

This document summarizes the skeleton code and project structure created for the refactored STIG generator workflow.

## What Was Created

### 1. Project-Level Instructions (`.cursorrules`)

A comprehensive project prompt that tells Cursor:
- What the project does (STIG → Ansible + Checker + CTP)
- External schema requirements (playbook structure, CSV headers)
- Internal data model (`StigControl` dataclass)
- Generation rules for each artifact type
- Quality/coverage requirements
- What NOT to do

**Location**: `.cursorrules`

### 2. Skeleton Scripts

#### `scripts/parse_stig.py`
- **Purpose**: Central parser that converts XCCDF XML → JSON
- **Status**: Skeleton with TODO placeholders
- **Key Functions**:
  - `parse_xccdf_file()` - Parse XML (needs implementation)
  - `save_controls_to_json()` - Save to JSON (implemented)
  - `load_controls_from_json()` - Load from JSON (implemented)
- **Next Step**: Integrate with `app.parsers.xccdf_parser.parse_xccdf()`

#### `scripts/generate_hardening.py`
- **Purpose**: Generate Ansible hardening playbook from JSON
- **Status**: Skeleton with category detection and placeholder tasks
- **Key Functions**:
  - `categorize_control()` - Detect control category (basic implementation)
  - `generate_file_permission_tasks()` - TODO
  - `generate_package_present_tasks()` - TODO
  - `generate_service_enabled_tasks()` - TODO
  - `generate_sysctl_tasks()` - TODO
- **Next Step**: Implement category-specific task generators

#### `scripts/generate_checker.py`
- **Purpose**: Generate Ansible checker playbook from JSON
- **Status**: Skeleton with placeholder check tasks
- **Key Functions**:
  - `generate_checker_task()` - Generate check task per control (basic implementation)
- **Next Step**: Extract actual check commands from `check_text`

#### `scripts/generate_ctp.py`
- **Purpose**: Generate CTP CSV from JSON
- **Status**: Skeleton with placeholder rows
- **Key Functions**:
  - `generate_ctp_rows_for_control()` - Generate 1-3 rows per control (basic implementation)
  - `format_nist_control_id()` - Format NIST IDs (needs implementation)
- **Next Step**: Extract actual commands and format properly

### 3. Coverage Test (`tests/test_coverage.py`)

A comprehensive test suite that verifies:
- All STIG IDs from JSON appear in hardening playbook
- All STIG IDs from JSON appear in checker playbook
- All STIG IDs from JSON appear in CTP CSV

**Status**: Fully functional!

## Directory Structure

```
stig_generator/
├── .cursorrules                    # Project-level AI instructions
├── scripts/
│   ├── __init__.py
│   ├── parse_stig.py              # XCCDF → JSON
│   ├── generate_hardening.py      # JSON → hardening playbook
│   ├── generate_checker.py        # JSON → checker playbook
│   └── generate_ctp.py            # JSON → CTP CSV
├── tests/
│   └── test_coverage.py           # Coverage verification
├── SCRIPTS_README.md              # Quick start guide
└── REFACTORING_SUMMARY.md         # This file
```

## Workflow

```
1. Parse:     XCCDF XML → parse_stig.py → JSON
2. Generate:  JSON → [generate_hardening.py, generate_checker.py, generate_ctp.py] → Artifacts
3. Verify:    test_coverage.py ensures 100% coverage
```

## Next Steps

### Immediate (Use Cursor to refine)

1. **Refine `parse_stig.py`**:
   - Import `app.parsers.xccdf_parser.parse_xccdf()`
   - Map to simplified `StigControl` dataclass
   - Test with RHEL 9 STIG

2. **Refine `generate_hardening.py`**:
   - Implement category-specific task generators
   - Use `app.generators.extractors` for value extraction
   - Test with parsed JSON

3. **Refine `generate_checker.py`**:
   - Extract check commands from `check_text`
   - Prefer Ansible modules over shell
   - Test with parsed JSON

4. **Refine `generate_ctp.py`**:
   - Extract commands and format properly
   - Generate 1-3 steps per control
   - Format NIST IDs correctly

### Future Enhancements

- Add support for quarterly STIG compilations
- Create data/stigs/ directory structure for organizing STIGs
- Add integration tests
- Document category detection logic
- Add error handling and validation

## Using Cursor

Each skeleton file has clear TODO markers and docstrings explaining what needs to be implemented. Use the prompts in `SCRIPTS_README.md` to guide Cursor's refinement.

The `.cursorrules` file ensures Cursor understands:
- The project's goals
- External schema requirements
- Quality standards
- What NOT to change

## Integration with Existing Code

The existing codebase in `app/` can be reused:
- `app.parsers.xccdf_parser` - Use for parsing
- `app.generators.extractors` - Use for command/value extraction
- `app.model.controls.StigControl` - Can be used directly or mapped to simplified version

The goal is a clean, maintainable pipeline that leverages existing logic while providing a clear separation of concerns.




