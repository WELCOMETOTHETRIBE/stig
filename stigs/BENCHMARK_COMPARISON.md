# SCAP Benchmark Comparison: benchmark/ vs benchmark2/

## Summary

The files in `benchmark2/` are **NIWC (Naval Information Warfare Center) enhanced versions** that are significantly more helpful than the standard DISA benchmarks in `benchmark/`.

## Key Differences

### 1. **SCAP Version**
- **benchmark/**: SCAP 1.3
- **benchmark2/**: SCAP 1.4 (newer standard)

### 2. **Control Coverage**
- **benchmark/**: 394 controls (RHEL 9 example)
- **benchmark2/**: 450 controls (RHEL 9 example) - **56 more controls!**

### 3. **Automation Coverage**

**benchmark/** (RHEL 9):
- OVAL (automated): 394 controls
- OCIL (manual questions): 0 controls

**benchmark2/** (RHEL 9):
- OVAL (automated): 410 controls
- OCIL (manual questions): **450 controls** (ALL controls have manual questions!)

### 4. **Additional Features in benchmark2/**

1. **OCIL Manual Questions**: Every control has OCIL manual questions derived from the STIG Manual
2. **Additional CPE Platforms**: Includes Rocky Linux 9 and AlmaLinux 9 (not just RHEL)
3. **Enhanced OVAL**: Additional OVAL checks (oval2.xml component)
4. **Signed/Validated**: Files are signed and validated
5. **More Recent**: Created November 2025 vs September 2025

### 5. **File Sizes**
- **benchmark/**: Generally smaller (RHEL 9: 2.7MB)
- **benchmark2/**: Larger due to additional content (RHEL 9: 4.8MB)

### 6. **Product Coverage**
- **benchmark/**: 6 products
- **benchmark2/**: 10 products (**4 additional products**):
  - Cisco IOS Router NDM (not just IOS-XE)
  - Cisco IOS Switch NDM (not just IOS-XE)
  - Cisco IOS-XE Switch NDM
  - MS IIS 10.0 Server

## Why benchmark2/ is More Helpful

### ✅ **Complete Coverage**
- **All controls have OCIL questions**: Even controls without OVAL checks have manual verification questions
- **More controls**: 56 additional controls in RHEL 9 example
- **Better automation detection**: More OVAL checks (410 vs 394)

### ✅ **Better for Manual Verification**
- OCIL questions provide structured manual verification steps
- Helps identify which controls truly need manual verification vs automated scanning

### ✅ **Multi-Platform Support**
- Supports Rocky Linux and AlmaLinux in addition to RHEL
- Better for organizations using RHEL-compatible distributions

### ✅ **Enhanced Metadata**
- Signed and validated files
- Clear attribution to NIWC SCC team
- Timestamp and version tracking

## Recommendation

**Use `benchmark2/` files for automation classification** because:

1. **More accurate automation detection**: 410 OVAL checks vs 394
2. **Complete manual question coverage**: All 450 controls have OCIL questions
3. **Better manual-only identification**: Controls without OVAL but with OCIL are clearly marked
4. **More controls**: Captures additional STIG controls
5. **Newer standard**: SCAP 1.4 vs 1.3

## File Mapping

| Product | benchmark/ | benchmark2/ | Notes |
|---------|-----------|-------------|-------|
| RHEL 9 | V2R6, SCAP 1.3 | V2R5, SCAP 1.4 | benchmark2 has more controls (450 vs 394) |
| RHEL 8 | V2R5, SCAP 1.3 | V2R4, SCAP 1.4 | Different STIG versions |
| Windows 11 | V2R6, SCAP 1.3 | V2R5, SCAP 1.4 | Different STIG versions |
| Windows Server 2022 | V2R6, SCAP 1.3 | V2R5, SCAP 1.4 | Different STIG versions |
| Cisco IOS-XE Router NDM | V3R4, SCAP 1.3 | V3R3, SCAP 1.4 | Different STIG versions |
| Cisco IOS-XE Router RTR | V3R4, SCAP 1.3 | V3R3, SCAP 1.4 | Different STIG versions |
| **Cisco IOS Router NDM** | ❌ Not available | ✅ V3R5, SCAP 1.4 | **NEW in benchmark2/** |
| **Cisco IOS Switch NDM** | ❌ Not available | ✅ V3R5, SCAP 1.4 | **NEW in benchmark2/** |
| **Cisco IOS-XE Switch NDM** | ❌ Not available | ✅ V3R4, SCAP 1.4 | **NEW in benchmark2/** |
| **MS IIS 10.0 Server** | ❌ Not available | ✅ V3R4, SCAP 1.4 | **NEW in benchmark2/** |

**Note**: 
- Some products have different STIG versions between the two directories. The benchmark2/ files may be based on slightly older STIG versions but are enhanced with OCIL questions.
- **benchmark2/ has 4 additional products** not available in benchmark/

## Usage Recommendation

When parsing STIG files with secondary artifacts:

```bash
# Use benchmark2/ for better automation detection
python scripts/parse_stig.py \
    --xccdf stigs/input/U_RHEL_9_STIG_V2R6_Manual-xccdf.xml \
    --output data/json/rhel9.json \
    --secondary-artifact stigs/benchmark2/U_RHEL_9_V2R5_STIG_SCAP_1-4_Benchmark-enhancedV8-signed.xml \
    --secondary-type scap
```

This will provide:
- More accurate automation classification (410 automated vs 394)
- Better identification of manual-only controls (40 controls with OCIL but no OVAL)
- Complete coverage of all 450 controls

## Conclusion

The `benchmark2/` files are **significantly more helpful** for automation classification because they:
1. Include OCIL manual questions for ALL controls
2. Have more OVAL automated checks
3. Cover more controls overall
4. Use the newer SCAP 1.4 standard
5. Support additional platforms (Rocky Linux, AlmaLinux)

**Recommendation**: Use `benchmark2/` files as the primary source for automation classification.

