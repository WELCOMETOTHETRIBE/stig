# Web Server Update Summary

## Problem

The web server (GUI) was showing old statistics:
- **81 Automatable** (18%)
- **366 Manual** (82%)

This was because the web server was using:
1. Old parser (`app.parsers.xccdf_parser`) instead of new `scripts/parse_stig.py`
2. Old classifier (`app.classifiers.automatable`) instead of SCAP-based classification
3. Old generators instead of new scripts
4. **Not using benchmark2/ files** at all

## Solution

Updated `web_server.py` to:
1. ✅ Use new `scripts/parse_stig.py` with benchmark2/ support
2. ✅ Auto-detect benchmark2/ files when available
3. ✅ Use new `scripts/generate_*.py` generators
4. ✅ Calculate statistics using new automation levels (automated/manual_only)
5. ✅ Return updated statistics to frontend

Updated `templates/index.html` to:
1. ✅ Display "Automated" instead of "Automatable"
2. ✅ Display "Manual-Only" instead of "Manual"
3. ✅ Add optional secondary artifact upload field
4. ✅ Add secondary artifact type selector

## Expected Results

After restarting the web server, the GUI should now show:
- **447 Total Controls**
- **367 Automated** (82%) - from SCAP OVAL checks
- **80 Manual-Only** (17%) - OCIL only or no checks

## How It Works

1. **User uploads STIG file** via GUI
2. **Web server auto-detects benchmark2/ file** if available (for RHEL 9, RHEL 8, etc.)
3. **Parses STIG with benchmark2/** using `scripts/parse_stig.py`
4. **Generates artifacts** using new scripts
5. **Returns correct statistics** to frontend

## Testing

To test the updated web server:

```bash
# Restart the web server
cd /Users/patrick/ansible/stig_generator
python3 web_server.py
```

Then:
1. Open http://localhost:4000
2. Upload `U_RHEL_9_STIG_V2R6_Manual-xccdf.xml`
3. Click "Generate Artifacts"
4. Verify statistics show:
   - **447 Total Controls**
   - **367 Automated** (82%)
   - **80 Manual-Only** (17%)

## Auto-Detection

The web server will automatically look for benchmark2/ files in:
- `stigs/benchmark2/U_RHEL_9*SCAP*Benchmark*.xml` for RHEL 9
- `stigs/benchmark2/U_RHEL_8*SCAP*Benchmark*.xml` for RHEL 8
- (More patterns can be added)

If found, it will use them automatically. Users can also manually upload a SCAP benchmark or Nessus scan via the optional field.




