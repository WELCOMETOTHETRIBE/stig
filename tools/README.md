# STIG Generator Tools

## sanity_check_playbooks.py

Comprehensive sanity checker for generated STIG hardening playbooks.

### Setup

Install PyYAML (required for YAML parsing):

```bash
pip install --user pyyaml
# or
python3 -m pip install --user pyyaml
```

### Usage

Run from the repo root:

```bash
python3 tools/sanity_check_playbooks.py
```

### What It Checks

1. **YAML Validity**: Uses `yaml.safe_load_all()` to verify valid YAML
2. **Play Header**: Verifies play name matches target OS (e.g., "RHEL 8 STIG Hardening")
3. **OS Assertions**: Checks `pre_tasks` contain correct OS family and version assertions
4. **Product Tags**: Ensures all STIG tasks have correct OS tags (`rhel8`, `rhel9`, `windows11`, `windows2022`)
5. **Automation Levels**:
   - `automation_automated` tasks must use real modules (not `debug`)
   - `automation_manual_only` tasks must be debug-only
6. **Windows Modules**: Windows playbooks must use `ansible.windows.*` or `community.windows.*` for automated tasks
7. **Ansible Syntax**: Runs `ansible-playbook --syntax-check` on each playbook

### Using as a "Gate" in Cursor

After modifying `scripts/generate_hardening.py`:

1. Regenerate playbooks:
   ```bash
   python3 scripts/generate_hardening.py --input data/json/rhel8_v2r5_controls.json --output output/ansible/stig_rhel8_hardening.yml --product rhel8
   # ... repeat for other playbooks
   ```

2. Run sanity check:
   ```bash
   python3 tools/sanity_check_playbooks.py
   ```

3. If it fails, fix issues in `generate_hardening.py` and repeat until it passes.

The script exits with non-zero status on failure, making it easy to use in automated workflows.

### Example Output

**Success:**
```
Checking RHEL 8 playbook: output/ansible/stig_rhel8_hardening.yml
  Running ansible-playbook --syntax-check...
  ✅ ansible-playbook --syntax-check passed
...

=== SANITY CHECK PASSED ===
```

**Failure:**
```
Checking RHEL 8 playbook: output/ansible/stig_rhel8_hardening.yml
...

=== SANITY CHECK FAILED ===
- [rhel8] Play name mismatch: expected 'RHEL 8 STIG Hardening', got 'RHEL 9 STIG Hardening'
- [rhel8] Task 'XYZ' missing OS tag 'rhel8' (tags: ['stig', 'rhel9'])
```




