# Data Directory

This directory contains STIG source files and generated JSON intermediate files.

## Structure

```
data/
├── stigs/              # Source XCCDF XML files organized by product and quarter
│   ├── rhel9/
│   │   ├── 2024_Q4/
│   │   │   └── U_RHEL_9_STIG_V1R5_20241212.xml
│   │   └── 2025_Q1/
│   │       └── U_RHEL_9_STIG_V1R6_20250315.xml
│   ├── rhel8/
│   │   └── 2024_Q4/
│   └── windows11/
│       └── 2024_Q4/
└── json/               # Generated JSON intermediate files
    ├── rhel9_2024_Q4_controls.json
    └── rhel9_2025_Q1_controls.json
```

## Usage

### Adding STIG Files

Place quarterly STIG compilations in the appropriate directory:

```bash
data/stigs/rhel9/2024_Q4/U_RHEL_9_STIG_V1R5_20241212.xml
```

### Parsing STIGs

```bash
python scripts/parse_stig.py \
  --xccdf data/stigs/rhel9/2024_Q4/U_RHEL_9_STIG_V1R5_20241212.xml \
  --output data/json/rhel9_2024_Q4_controls.json
```

### Generating Artifacts

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

## Why Commit STIG Files?

Committing STIG XML files to the repo allows:
- Cursor to see representative examples when editing code
- Consistent testing across team members
- Version control of which STIG versions were used
- Easy reference for understanding STIG structure

Note: Cursor doesn't "learn" from files like a training run, but it can use them as context when you reference them in prompts.




