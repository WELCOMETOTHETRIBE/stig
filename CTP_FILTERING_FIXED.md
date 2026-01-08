# CTP Filtering Fix

## Problem

The CTP CSV was generating rows for **ALL controls** (447 controls = 649 rows), but it should only include **manual controls** that cannot be automated by SCAP/OVAL/Nessus.

## Solution

Updated `generate_ctp_csv()` to filter controls before generating rows:

### Before
- Generated CTP rows for ALL 447 controls
- Result: 649 rows (1-3 rows per control)

### After
- Filters to only manual controls: `automation_level in ["manual", "not_scannable_with_nessus"]`
- Result: 7 rows (1 row per manual control) + 1 header = 8 total lines

## Logic

**CTP is for manual testing only:**
- ✅ **Include**: Controls that are `manual` or `not_scannable_with_nessus`
- ❌ **Exclude**: Controls that are `automated`, `semi_automated`, `scannable_with_nessus`, or `automatable`

**Rationale:**
- Automated controls are tested via SCAP/OVAL/Nessus scanning
- Manual controls require human verification and need CTP steps
- CTP should be minimal - only the controls that can't be automated

## Results

### RHEL 9 STIG V2R6
- **Total Controls**: 447
- **Automated (excluded from CTP)**: 440 (98%)
- **Manual (included in CTP)**: 7 (1%)
- **CTP Rows**: 7 (one per manual control)
- **CTP File Size**: 8 lines (1 header + 7 rows)

### Sample Manual Controls in CTP
1. SV-257857r991589_rule - Removable media file system restrictions
2. SV-257858r991589_rule - Special devices on removable media
3. SV-257859r991589_rule - Setuid/setgid on removable media
4. SV-258028r991589_rule - dconf policy matching
5. SV-258031r1134920_rule - GNOME Ctrl-Alt-Del configuration
6. SV-258038r1045128_rule - Unauthorized peripheral blocking
7. SV-258047r1101951_rule - Temporary account expiration

## Updated Functions

1. **`generate_ctp_csv()`**: Now filters to manual controls only
2. **`verify_coverage()`**: Now only verifies manual controls are present

## Status

✅ **CTP Filtering**: Fixed
✅ **File Size**: Reduced from 649 rows to 8 lines
✅ **Content**: Only manual controls included
✅ **Coverage**: All 7 manual controls present

The CTP now correctly represents only the controls that require manual testing!




