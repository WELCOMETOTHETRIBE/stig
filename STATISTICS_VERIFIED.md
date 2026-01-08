# Statistics Verification

## Current Status (After Regeneration)

### JSON File (`data/json/rhel9_v2r6_controls.json`)
- **Total Controls**: 447
- **automated**: 394 (88%) - from SCAP OVAL
- **scannable_with_nessus**: 46 (10%) - fallback
- **not_scannable_with_nessus**: 7 (1%) - fallback

### Hardening Playbook (`output/ansible/stig_rhel9_hardening.yml`)
- **Total Controls**: 447
- **Automated (OVAL)**: 440 (98%) ✅
  - Includes: 394 automated + 46 scannable_with_nessus
- **Manual**: 7 (1%) ✅
- **Tags**: `automation_automated` (447 instances)

### Checker Playbook (`output/ansible/stig_rhel9_checker.yml`)
- **Total Controls**: 447
- **Automated (OVAL)**: 440 (98%) ✅
- **Manual**: 7 (1%) ✅
- **Tags**: `validate_automated` (430 instances)

### CTP CSV (`output/ctp/stig_rhel9_ctp.csv`)
- **Total Rows**: 513 (1-3 rows per control)
- **SCAP References**: Present in Notes column ✅
- **Commands**: Cleaned (backticks removed) ✅

## If You're Seeing Old Statistics

If you see:
- **81 Automatable**
- **366 Manual**

This indicates you're viewing an **old file** that was generated before SCAP integration. 

### Solution
1. **Regenerate the files** using the updated JSON:
   ```bash
   python scripts/generate_hardening.py \
     --input data/json/rhel9_v2r6_controls.json \
     --output output/ansible/stig_rhel9_hardening.yml \
     --product rhel9
   
   python scripts/generate_checker.py \
     --input data/json/rhel9_v2r6_controls.json \
     --output output/ansible/stig_rhel9_checker.yml \
     --product rhel9
   
   python scripts/generate_ctp.py \
     --input data/json/rhel9_v2r6_controls.json \
     --output output/ctp/stig_rhel9_ctp.csv
   ```

2. **Verify the header** shows:
   - `Automated (OVAL): 440 (98%)`
   - `Manual: 7 (1%)`

3. **Check file timestamps** - regenerated files should have recent timestamps

## Expected Statistics

With SCAP integration:
- **~88% Automated** (from SCAP OVAL checks)
- **~10% Scannable** (fallback for controls not in SCAP but with check commands)
- **~1-2% Manual** (no SCAP support and no check commands)

The old statistics (81/366) were from the legacy classifier before SCAP integration.




