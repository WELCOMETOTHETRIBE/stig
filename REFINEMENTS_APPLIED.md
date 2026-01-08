# Refinements Applied to Generators

## Summary

Refined the generator scripts based on review of the RHEL 8 generated artifacts to improve:
1. CTP language cleanliness (remove policy boilerplate)
2. Category detection accuracy (reduce debug tasks)
3. Command cleaning (remove backticks, fix incomplete commands)

## Changes Made

### 1. CTP Generator (`scripts/generate_ctp.py`)

#### Fixed: Language Cleaning
- **`_extract_expected_result()`**: Completely rewritten to:
  - Remove "Must:" prefixes
  - Remove "If it does not, this is a finding." / "If it is true, this is a finding." suffixes
  - Extract actual conditions, not policy statements
  - Convert to clear, actionable descriptions (e.g., "Should be: SHA512" instead of "Must: ENCRYPT_METHOD does not equal SHA512 or greater. If it is not, this is a finding.")
  - Handle specific patterns (file permissions, owner/group, value requirements)

#### Fixed: Command Cleaning
- **`_clean_command()`**: Enhanced to:
  - Remove backticks from commands
  - Detect and skip incomplete commands (e.g., "grep -" without pattern)
  - Detect and skip placeholder paths (e.g., "/path/to/file")
  - Return `None` for invalid commands so they're filtered out

#### Fixed: Screen Output
- **`_extract_screen_output()`**: Enhanced to:
  - Extract actual example outputs, not just pattern names (e.g., "-iH")
  - Show configuration examples when available
  - Show file locations when available
  - Skip pattern-only outputs

#### Fixed: Post-Processing
- Added cleanup in `generate_ctp_rows_for_control()` to:
  - Remove any remaining "Must:" prefixes
  - Remove any remaining "If it does not..." suffixes
  - Ensure clean, auditor-friendly language

### 2. Hardening Generator (`scripts/generate_hardening.py`)

#### Fixed: Category Detection
- **`categorize_control()`**: Enhanced to:
  - First check existing category from parser (if not "other")
  - Map legacy category names (e.g., "file_permission" → "file_permissions")
  - Use regex patterns to detect actual commands in `fix_text`, not just keywords
  - Better detection of:
    - File permissions (chmod patterns, mode values)
    - Services (systemctl commands, enable/disable detection)
    - Packages (yum/dnf/rpm/apt commands, install/remove detection)
    - Sysctl (sysctl commands, /proc/sys paths)
    - Config files (lineinfile, sed, grep patterns, specific file paths)

#### Improved: Pattern Matching
- Uses regex to find actual command patterns in `fix_text`
- Checks for specific file paths (e.g., "/etc/login.defs", "/etc/pam.d/")
- Better context awareness (e.g., "not installed" → package_absent)

## Expected Improvements

### CTP CSV
- ✅ Commands without backticks: `Run: cat /etc/redhat-release` instead of `Run \`cat /etc/redhat-release\``
- ✅ Clean expected results: `"Should be: SHA512"` instead of `"Must: ENCRYPT_METHOD does not equal SHA512 or greater. If it is not, this is a finding."`
- ✅ Actual example outputs instead of pattern names
- ✅ No incomplete commands (filtered out)

### Hardening Playbook
- ✅ More controls categorized correctly (fewer "other" → fewer debug tasks)
- ✅ Better use of existing category from parser
- ✅ More accurate service enable/disable detection
- ✅ Better package install/remove detection

## Testing

To test the refinements:

1. **Regenerate CTP CSV**:
```bash
python scripts/generate_ctp.py \
  --input data/json/rhel8_controls.json \
  --output ctp/stig_rhel8_ctp_refined.csv
```

2. **Regenerate Hardening Playbook**:
```bash
python scripts/generate_hardening.py \
  --input data/json/rhel8_controls.json \
  --output ansible/stig_rhel8_hardening_refined.yml \
  --product rhel8
```

3. **Compare Results**:
- Check that CTP language is cleaner (no "Must:", no "If it does not...")
- Check that commands don't have backticks
- Check that incomplete commands are filtered out
- Check that hardening playbook has fewer debug tasks

## Next Steps

1. Test with RHEL 8 controls
2. Verify improvements in output quality
3. If needed, further refine:
   - More specific pattern matching
   - Better extraction of values
   - Handling of edge cases

## Files Modified

1. ✅ `scripts/generate_ctp.py` - Language cleaning, command cleaning, screen output
2. ✅ `scripts/generate_hardening.py` - Category detection improvements




