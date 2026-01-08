# Cursor Setup Complete ✅

Your STIG generator is now fully configured for incremental refinement with Cursor.

## What's Been Set Up

### 1. Project-Level Instructions
- **`.cursorrules`** - Comprehensive source of truth for Cursor
  - External contracts (CSV headers, playbook structure)
  - Internal data model
  - Generation rules for each artifact
  - Coverage & quality requirements
  - What NOT to change

### 2. Directory Structure
```
stig_generator/
├── .cursorrules                    # ← Cursor's "brain"
├── scripts/                        # ← Refactored generators
│   ├── parse_stig.py              # XCCDF → JSON
│   ├── generate_hardening.py      # JSON → hardening playbook
│   ├── generate_checker.py        # JSON → checker playbook
│   └── generate_ctp.py            # JSON → CTP CSV
├── data/
│   ├── stigs/                     # ← Place quarterly STIGs here
│   │   ├── rhel9/2024_Q4/
│   │   ├── rhel9/2025_Q1/
│   │   └── ...
│   └── json/                      # ← Generated JSON intermediates
├── examples/                      # ← Style references for Cursor
│   └── rhel9/
│       ├── stig_rhel9_hardening_example.yml
│       ├── stig_rhel9_checker_example.yml
│       └── stig_rhel9_ctp_example.csv
└── tests/
    └── test_coverage.py           # ← 100% coverage verification
```

### 3. Documentation
- **`REFACTORING_SUMMARY.md`** - Architecture overview
- **`SCRIPTS_README.md`** - Quick start guide
- **`CURSOR_WORKFLOW.md`** - Step-by-step refinement guide
- **`data/README.md`** - Data directory structure
- **`examples/README.md`** - Example outputs guide

### 4. Coverage Testing
- **`tests/test_coverage.py`** - Fully functional coverage verification
  - Ensures all STIG IDs appear in all artifacts
  - Can be run after each refinement

## Next Steps

### Immediate: Start with Parsing

1. **Open** `scripts/parse_stig.py` in Cursor
2. **Use the prompt** from `CURSOR_WORKFLOW.md` section 1
3. **Test** with an existing STIG file
4. **Verify** JSON output is correct

### Then: Refine Generators

Follow the workflow in `CURSOR_WORKFLOW.md`:
1. Hardening generator (category-specific tasks)
2. Checker generator (module-based checks)
3. CTP generator (clean, auditor-friendly language)

### After Each Change

```bash
# Run coverage tests
pytest tests/test_coverage.py \
  --json-path data/json/rhel9_test_controls.json \
  --hardening-path ansible/stig_rhel9_test_hardening.yml \
  --checker-path ansible/stig_rhel9_test_checker.yml \
  --ctp-path ctp/stig_rhel9_test_ctp.csv
```

## Key Files to Reference

When working with Cursor:

1. **`.cursorrules`** - Always reference this for project rules
2. **`REFACTORING_SUMMARY.md`** - Architecture decisions
3. **`examples/rhel9/`** - Style examples for tone and structure
4. **`CURSOR_WORKFLOW.md`** - Step-by-step prompts for each script

## How Cursor Will Help

Cursor now understands:
- ✅ The project's goals and constraints
- ✅ External schema requirements (CSV headers, playbook structure)
- ✅ Internal data model (`StigControl`)
- ✅ Generation rules for each artifact type
- ✅ Quality standards (100% coverage, clean language)
- ✅ What NOT to change (test expectations, schemas)

When you ask Cursor to refine a script, it will:
- Follow the rules in `.cursorrules`
- Reference the architecture in `REFACTORING_SUMMARY.md`
- Match the style in `examples/rhel9/`
- Ensure coverage tests continue to pass

## Quick Reference

### Parse a STIG
```bash
python scripts/parse_stig.py \
  --xccdf data/stigs/rhel9/2024_Q4/U_RHEL_9_STIG_V1R5_20241212.xml \
  --output data/json/rhel9_2024_Q4_controls.json
```

### Generate Artifacts
```bash
# Hardening
python scripts/generate_hardening.py \
  --input data/json/rhel9_2024_Q4_controls.json \
  --output ansible/stig_rhel9_2024_Q4_hardening.yml \
  --product rhel9

# Checker
python scripts/generate_checker.py \
  --input data/json/rhel9_2024_Q4_controls.json \
  --output ansible/stig_rhel9_2024_Q4_checker.yml \
  --product rhel9

# CTP
python scripts/generate_ctp.py \
  --input data/json/rhel9_2024_Q4_controls.json \
  --output ctp/stig_rhel9_2024_Q4_ctp.csv
```

### Verify Coverage
```bash
pytest tests/test_coverage.py \
  --json-path data/json/rhel9_2024_Q4_controls.json \
  --hardening-path ansible/stig_rhel9_2024_Q4_hardening.yml \
  --checker-path ansible/stig_rhel9_2024_Q4_checker.yml \
  --ctp-path ctp/stig_rhel9_2024_Q4_ctp.csv
```

## You're Ready! 🚀

Everything is set up. Start with `CURSOR_WORKFLOW.md` and begin refining `parse_stig.py`.




