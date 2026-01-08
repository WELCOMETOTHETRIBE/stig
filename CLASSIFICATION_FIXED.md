# Classification Fix Summary

## Problem Identified

The RHEL 9 output files were generated from an **old JSON file** that was created before SCAP integration. The JSON showed:
- `semi_automatable: 432 (96%)` ❌ (old classifier output)
- `manual: 15 (3%)`

This caused the generated files to use old terminology and incorrect classification.

## Root Cause

1. **JSON file was outdated**: Generated before SCAP integration was added
2. **SCAP integration was working correctly** in the parser, but the JSON wasn't regenerated
3. **Generators were using old JSON** with `semi_automatable` values

## Solution

### 1. Regenerated JSON with SCAP Integration ✅

```bash
python scripts/parse_stig.py \
  --xccdf stigs/data/U_RHEL_9_V2R6_STIG/U_RHEL_9_V2R6_Manual_STIG/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml \
  --output data/json/rhel9_v2r6_controls.json
```

**New JSON shows correct SCAP-based classification:**
- `automated: 394 (88%)` ✅ (from SCAP OVAL checks)
- `scannable_with_nessus: 46 (10%)` ✅ (fallback for controls not in SCAP)
- `not_scannable_with_nessus: 7 (1%)` ✅ (fallback for controls with no check commands)

### 2. Regenerated All Output Files ✅

**Hardening Playbook:**
- Header now shows: `Automated (OVAL): 440 (98%)` ✅
- Tags use: `automation_automated` ✅
- 394 SCAP-automated + 46 fallback scannable = 440 total automated

**Checker Playbook:**
- Header shows SCAP-based counts ✅
- Tags use: `validate_automated`, `validate_manual` ✅

**CTP CSV:**
- Commands cleaned (backticks removed) ✅
- Policy language removed ✅
- SCAP/OVAL references in Notes column ✅

## Results

### Before (Old JSON)
- `semi_automatable: 432 (96%)` ❌
- Old terminology throughout
- No SCAP integration

### After (New JSON with SCAP)
- `automated: 394 (88%)` ✅ (from SCAP)
- `scannable_with_nessus: 46 (10%)` ✅ (fallback)
- `not_scannable_with_nessus: 7 (1%)` ✅ (fallback)
- SCAP-based tags and terminology ✅

## Key Insight

**The SCAP integration was working correctly all along!** The issue was that the JSON file needed to be regenerated to include the SCAP data. Once regenerated, all three output files (hardening, checker, CTP) now correctly reflect:

1. **SCAP-based automation levels** (automated, semi_automated, manual)
2. **Proper tags** (automation_automated, validate_automated, etc.)
3. **Correct headers** showing SCAP counts
4. **SCAP references** in CTP Notes column

## Next Steps

For future STIGs:
1. **Always regenerate JSON** after SCAP integration updates
2. **Verify JSON contains SCAP data** before generating output files
3. **Check automation_level values** in JSON match SCAP expectations

## Status

✅ **JSON Regenerated** with SCAP data
✅ **Hardening Playbook** regenerated with correct tags
✅ **Checker Playbook** regenerated with correct tags  
✅ **CTP CSV** regenerated with SCAP references
✅ **Classification Working Correctly**

All files now properly reflect SCAP-based automation levels!




