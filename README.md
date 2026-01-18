# FolderGuard
A cybersecurity portfolio project which is a Detection System for Unauthorized File Changes and Ransomware Activity

Shared folders often contain important files (invoices, reports, configs). Unauthorized edits, accidental deletions, or ransomware encryption can go unnoticed until damage is done.

FolderGuard creates a trusted baseline of file hashes and verifies the folder later to detect:
- Modified files
- Deleted files
- Unexpected new files

It generates incident-ready reports and a simple risk level (LOW/MEDIUM/HIGH) to highlight suspicious mass changes.


## To Create a baseline
Put the location to the folder you want to set as the baseline in the *sample_data* section.
```
python integrity_checker.py init --folder sample_data --out manifest.json
```
A manifest.json will be created.

## To Verify integrity
Put the location to the folder you set as the baseline in the *sample_data* section to verify.
```
python integrity_checker.py verify --folder sample_data --manifest manifest.json
```

### Outputs:
output/report.txt

output/report.json



### Practical Uses:
- Early warning for ransomware-style mass file changes
- Detecting unauthorized changes in shared folders
- Verifying backup integrity
- Evidence collection during incident response
