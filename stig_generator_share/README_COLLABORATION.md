# STIG Generator - Collaboration Package

## Welcome!

This package contains the core STIG Automation Generator codebase for collaboration. This tool converts DISA STIG XCCDF XML files into Ansible playbooks and compliance documentation.

## Quick Start

### 1. Prerequisites

- **Python 3.11 or higher** (Python 3.12+ recommended)
- **pip** (Python package manager)
- **Ansible** (for validating generated playbooks)

### 2. Setup

```bash
# Create a virtual environment (recommended)
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# OR install as an editable package
pip install -e .
```

### 3. Verify Installation

```bash
# Test the parser
python scripts/parse_stig.py --help

# Test the generators
python scripts/generate_hardening.py --help
python scripts/generate_checker.py --help
python scripts/generate_ctp.py --help
```

## Project Structure

```
stig_generator_share/
├── scripts/                    # Main generation scripts
│   ├── parse_stig.py          # Parse XCCDF XML → JSON
│   ├── generate_hardening.py  # Generate hardening playbooks
│   ├── generate_checker.py    # Generate checker playbooks
│   ├── generate_ctp.py        # Generate CTP documents
│   ├── parse_scap_benchmark.py # Parse SCAP benchmarks
│   └── parse_nessus_scan.py    # Parse Nessus scans
├── app/                        # Core application library
│   ├── parsers/               # XML parsers
│   ├── model/                 # Data models
│   ├── classifiers/           # Control classification
│   └── generators/            # Legacy generators (reference)
├── tools/                      # Validation tools
│   └── sanity_check_playbooks.py  # Playbook validation
├── tests/                      # Test suite
│   ├── test_coverage.py       # Coverage verification
│   ├── test_parsers.py        # Parser tests
│   └── test_generators.py     # Generator tests
├── web_server.py              # Web UI (optional)
├── templates/                  # Web UI templates
├── pyproject.toml             # Project configuration
├── requirements.txt          # Python dependencies
└── pytest.ini                 # Test configuration
```

## Basic Usage

### Complete Workflow Example

```bash
# 1. Parse STIG XML file to JSON
python scripts/parse_stig.py \
    --xccdf path/to/U_RHEL_9_V2R6_STIG_Manual-xccdf.xml \
    --output data/rhel9_controls.json \
    --secondary-artifact path/to/U_RHEL_9_V2R6_STIG_SCAP_Benchmark.xml \
    --secondary-type scap

# 2. Generate hardening playbook
python scripts/generate_hardening.py \
    --input data/rhel9_controls.json \
    --output output/stig_rhel9_hardening.yml \
    --product rhel9

# 3. Generate checker playbook
python scripts/generate_checker.py \
    --input data/rhel9_controls.json \
    --output output/stig_rhel9_checker.yml \
    --product rhel9

# 4. Generate CTP document
python scripts/generate_ctp.py \
    --input data/rhel9_controls.json \
    --output output/stig_rhel9_ctp.csv \
    --manual-only
```

### Individual Script Usage

#### Parse STIG File

```bash
python scripts/parse_stig.py \
    --xccdf <path_to_stig_xml> \
    --output <output_json_file> \
    [--secondary-artifact <scap_or_nessus_file>] \
    [--secondary-type <scap|nessus>]
```

**Options:**
- `--xccdf`: Path to DISA STIG XCCDF XML file (required)
- `--output`: Path to output JSON file (required)
- `--secondary-artifact`: Optional SCAP benchmark or Nessus scan file
- `--secondary-type`: Type of secondary artifact (`scap` or `nessus`)

#### Generate Hardening Playbook

```bash
python scripts/generate_hardening.py \
    --input <parsed_json_file> \
    --output <output_playbook_yml> \
    --product <rhel8|rhel9|windows11|windows2022>
```

**Options:**
- `--input`: Path to JSON file from `parse_stig.py` (required)
- `--output`: Path to output Ansible playbook (required)
- `--product`: Product identifier (required)

#### Generate Checker Playbook

```bash
python scripts/generate_checker.py \
    --input <parsed_json_file> \
    --output <output_playbook_yml> \
    --product <rhel8|rhel9|windows11|windows2022>
```

#### Generate CTP Document

```bash
python scripts/generate_ctp.py \
    --input <parsed_json_file> \
    --output <output_csv_file> \
    [--manual-only]
```

**Options:**
- `--manual-only`: Only include manual-only controls (recommended)

## Supported Products

- **RHEL 8** (`rhel8`)
- **RHEL 9** (`rhel9`)
- **Windows 11** (`windows11`)
- **Windows Server 2022** (`windows2022`)
- **Cisco IOS Switch** (NDM, L2S, RTR)

## Validation and Testing

### Validate Generated Playbooks

```bash
# Run sanity checks on generated playbooks
python tools/sanity_check_playbooks.py

# Or validate a specific playbook
ansible-playbook --syntax-check output/stig_rhel9_hardening.yml
```

### Run Test Suite

```bash
# Run all tests
pytest

# Run specific test
pytest tests/test_coverage.py

# Run with verbose output
pytest -v
```

### Verify Coverage

```bash
python tests/test_coverage.py \
    --json-path data/rhel9_controls.json \
    --hardening-path output/stig_rhel9_hardening.yml \
    --checker-path output/stig_rhel9_checker.yml \
    --ctp-path output/stig_rhel9_ctp.csv
```

## Web Interface (Optional)

If you want to use the web-based UI:

```bash
# Start the web server
python web_server.py

# Access at http://localhost:4002
```

The web interface provides:
- Drag-and-drop STIG file upload
- Real-time statistics
- One-click artifact generation
- Direct download of generated files

## Key Features

### 1. Intelligent Control Classification

The system automatically classifies STIG controls:
- **Automated Controls** (80%+): Fully automatable using Ansible
- **Manual-Only Controls** (15-20%): Require human verification

Classification uses SCAP benchmark analysis when available.

### 2. Production-Ready Output

- Valid YAML syntax (validated with `ansible-playbook --syntax-check`)
- Idempotent Ansible tasks
- Proper OS-specific modules
- Clean configuration extraction (no prose in technical fields)

### 3. Multi-Platform Support

- Linux (RHEL 8, RHEL 9)
- Windows (Windows 11, Windows Server 2022)
- Network devices (Cisco IOS)

## Development Workflow

### Making Changes

1. **Create a branch** (if using version control)
2. **Make your changes** to the relevant scripts
3. **Test your changes**:
   ```bash
   # Run tests
   pytest
   
   # Generate sample output
   python scripts/parse_stig.py --xccdf <test_file> --output test.json
   python scripts/generate_hardening.py --input test.json --output test.yml --product rhel9
   
   # Validate output
   python tools/sanity_check_playbooks.py
   ansible-playbook --syntax-check test.yml
   ```
4. **Verify coverage** - Ensure all STIG controls are still covered

### Code Organization

- **`scripts/`**: Main entry points for the tool
- **`app/`**: Reusable library code
  - `parsers/`: XML parsing logic
  - `model/`: Data structures
  - `classifiers/`: Control classification
  - `generators/`: Legacy generators (for reference)
- **`tools/`**: Utility scripts for validation
- **`tests/`**: Test suite

## Common Tasks

### Adding Support for a New Product

1. Update `scripts/parse_stig.py` to recognize the new product
2. Add product-specific patterns to `scripts/generate_hardening.py`
3. Update `tools/sanity_check_playbooks.py` with new product metadata
4. Test with a sample STIG file

### Improving Control Classification

- Modify `app/classifiers/automatable.py`
- Update SCAP benchmark parsing in `app/parsers/scap_benchmark.py`
- Test with various STIG files

### Enhancing Task Generation

- Update category-specific generators in `scripts/generate_hardening.py`
- Use extractors from `app/generators/extractors.py`
- Ensure proper Ansible module usage

## Troubleshooting

### Import Errors

```bash
# Make sure you're in the virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### YAML Syntax Errors

```bash
# Validate with Ansible
ansible-playbook --syntax-check <playbook_file>

# Check with sanity checker
python tools/sanity_check_playbooks.py
```

### Missing Dependencies

```bash
# Install all dependencies
pip install -r requirements.txt

# For web server (optional)
pip install flask
```

## Getting Help

- Check `SCRIPTS_README.md` for detailed script documentation
- Review test files in `tests/` for usage examples
- Check existing generated playbooks in `output/` (if provided)

## Next Steps

1. **Set up your environment** (see Setup section above)
2. **Test with a sample STIG file** to verify everything works
3. **Review the code structure** to understand the architecture
4. **Start making your contributions!**

## Notes

- All generated playbooks should pass `ansible-playbook --syntax-check`
- The sanity checker (`tools/sanity_check_playbooks.py`) validates:
  - YAML syntax
  - OS-specific wrappers
  - Product tags
  - Module usage
  - Windows-specific modules
- Always test changes with multiple STIG files before committing

---

**Happy coding!** 🚀

