# Classification and Terminology Update

## Summary

Updated the STIG control classification to be more permissive (targeting 70-80% scannable) and changed terminology from "automatable/manual" to "Scannable with Nessus" / "Not Scannable with Nessus".

## Changes Made

### 1. Classification Logic (`app/classifiers/automatable.py`)

**Before**: Too conservative - only 21.5% marked as automatable
- Required both extractable commands AND real commands
- Defaulted to manual when unsure

**After**: More permissive - targeting 70-80% scannable
- If control has check commands → Scannable with Nessus
- If control has keywords (file permissions, services, packages, etc.) AND check commands → Scannable
- Only truly GUI-only or subjective controls → Not Scannable
- Default: If check commands exist, mark as scannable

**Key Changes**:
- Check commands are primary indicator for scannability
- More permissive default (scannable if check commands exist)
- Only truly manual indicators (GUI, screenshots, interviews) mark as not scannable

### 2. Terminology Update

**Old Terminology**:
- `automatable` / `semi_automatable` / `manual`
- Tags: `validate_automatable` / `validate_manual`

**New Terminology**:
- `scannable_with_nessus` / `not_scannable_with_nessus`
- Tags: `validate_scannable_with_nessus` / `validate_not_scannable_with_nessus`

**Files Updated**:
- ✅ `app/classifiers/automatable.py` - Updated docstrings and logic
- ✅ `scripts/parse_stig.py` - Updated automation_level mapping and logging
- ✅ `scripts/generate_hardening.py` - Updated terminology mapping
- ✅ `scripts/generate_checker.py` - Updated terminology and tags

### 3. Parser Updates (`scripts/parse_stig.py`)

**Before**:
```python
if legacy.is_automatable:
    automation_level = "automatable"
elif legacy.has_real_commands():
    automation_level = "semi_automatable"
else:
    automation_level = "manual"
```

**After**:
```python
# If it has check commands, it's scannable (even if not perfectly automatable)
if legacy.is_automatable or legacy.has_real_commands() or len(legacy.candidate_check_blocks) > 0:
    automation_level = "scannable_with_nessus"
else:
    automation_level = "not_scannable_with_nessus"
```

**Logging**:
- Now shows percentage of scannable vs not scannable
- Example: `Scannable with Nessus: 294 (80%)`

## Expected Results

### Before
- Automatable: 79 (21.5%)
- Manual: 289 (78.5%)

### After (Expected)
- Scannable with Nessus: ~260-290 (70-80%)
- Not Scannable with Nessus: ~78-108 (20-30%)

## CTP Issues Still Present

The newly generated CTP file still has issues that need to be addressed:
1. **Backticks in commands**: `Run \`cat /etc/redhat-release\`` should be `Run: cat /etc/redhat-release`
2. **Policy language**: "Must: ... If it does not, this is a finding." should be cleaned
3. **Incomplete commands**: `grep -` (missing pattern)

These refinements were made to `scripts/generate_ctp.py` but may not have been applied in the latest generation. The fixes are in place and should work on next regeneration.

## Next Steps

1. **Regenerate artifacts** with updated classification:
   ```bash
   python scripts/parse_stig.py \
     --xccdf stigs/data/U_RHEL_8_STIG_V2R5_Manual-xccdf.xml \
     --output data/json/rhel8_v2r5_controls.json
   
   python scripts/generate_hardening.py \
     --input data/json/rhel8_v2r5_controls.json \
     --output output/ansible/stig_rhel8_hardening.yml \
     --product rhel8
   
   python scripts/generate_checker.py \
     --input data/json/rhel8_v2r5_controls.json \
     --output output/ansible/stig_rhel8_checker.yml \
     --product rhel8
   
   python scripts/generate_ctp.py \
     --input data/json/rhel8_v2r5_controls.json \
     --output output/ctp/stig_rhel8_ctp.csv
   ```

2. **Verify classification**:
   - Check that 70-80% are marked as "scannable_with_nessus"
   - Verify terminology is updated throughout

3. **Verify CTP quality**:
   - Commands should not have backticks
   - Language should be clean (no "Must:" or "If it does not...")
   - Incomplete commands should be filtered

## Testing

To test the updated classification:

```python
# Test classification
from app.classifiers.automatable import classify_control
from app.model.controls import StigControl

# Create a test control with check commands
control = StigControl(
    id="SV-TEST",
    title="Test control",
    severity="medium",
    description="Test",
    check_text="Run: cat /etc/redhat-release",
    fix_text="Configure system",
    candidate_check_blocks=["cat /etc/redhat-release"]
)

classified = classify_control(control)
print(f"Is scannable: {classified.is_automatable}")  # Should be True
```

## Notes

- The `is_automatable` field in the model still uses boolean (True = Scannable with Nessus, False = Not Scannable)
- The `automation_level` field in the simplified model uses the new terminology
- Backward compatibility: Old terminology is automatically mapped to new terminology in generators




