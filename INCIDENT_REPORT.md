# Incident Report (Simulation): Folder Integrity Alert

**Tool:** FolderGuard (SHA-256 Integrity Monitor)  
**Date:** (18/01/2026)  
**Severity:** (MEDIUM)

## Summary
Integrity verification detected unexpected changes in a protected folder.

## Evidence
- `output/report.txt`
- `output/report.json`

## Observed Changes
- Modified files: 1  
- Removed files: 1
- Added files: 11
- Unchanged files: 1

## Impact
Unexpected changes may indicate unauthorized access, tampering, or ransomware encryption activity.

## Response Actions (Recommended)
1. Isolate affected system (if real environment)
2. Identify changed files from report
3. Restore from last known backup (if needed)
4. Review permissions and access logs
5. Re-run integrity scan after remediation

## Prevention
- Least privilege access control
- Scheduled integrity verification
- Regular backups + offline copies
