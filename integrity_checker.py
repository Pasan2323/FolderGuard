import argparse
import hashlib
import json
import os
from datetime import datetime

CHUNK_SIZE = 1024 * 1024  # 1MB

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def scan_folder(folder: str) -> dict:
    manifest = {}
    for root, _, files in os.walk(folder):
        for name in files:
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, folder)

            # Skip hidden files like .DS_Store
            if rel_path.startswith("."):
                continue

            manifest[rel_path] = {
                "sha256": sha256_file(full_path),
                "size_bytes": os.path.getsize(full_path),
            }
    return manifest

def save_manifest(manifest: dict, out_path: str, folder: str):
    data = {
        "project": "FolderGuard",
        "folder": os.path.abspath(folder),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "files": manifest
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_manifest(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def risk_level(added: int, removed: int, modified: int) -> str:
    total = added + removed + modified
    # Simple ransomware-style heuristic
    if modified >= 10 or total >= 15:
        return "HIGH"
    if modified >= 3 or total >= 5:
        return "MEDIUM"
    return "LOW"

def verify(folder: str, manifest_path: str) -> dict:
    old = load_manifest(manifest_path)["files"]
    new = scan_folder(folder)

    old_set = set(old.keys())
    new_set = set(new.keys())

    added = sorted(list(new_set - old_set))
    removed = sorted(list(old_set - new_set))

    modified = []
    unchanged = []

    for p in sorted(list(old_set & new_set)):
        if old[p]["sha256"] != new[p]["sha256"]:
            modified.append(p)
        else:
            unchanged.append(p)

    lvl = risk_level(len(added), len(removed), len(modified))

    return {
        "project": "FolderGuard",
        "verified_at": datetime.utcnow().isoformat() + "Z",
        "folder": os.path.abspath(folder),
        "manifest_used": os.path.abspath(manifest_path),
        "risk_level": lvl,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
            "unchanged": len(unchanged)
        },
        "details": {
            "added": added,
            "removed": removed,
            "modified": modified,
            "unchanged": unchanged
        }
    }

def write_report(report: dict, out_path: str):
    lines = []
    lines.append("FolderGuard - Integrity Monitor Report")
    lines.append(f"Verified at: {report['verified_at']}")
    lines.append(f"Folder: {report['folder']}")
    lines.append(f"Manifest: {report['manifest_used']}")
    lines.append(f"Risk level: {report['risk_level']}")
    lines.append("")
    lines.append("Summary:")
    for k, v in report["summary"].items():
        lines.append(f"  - {k}: {v}")
    lines.append("")
    lines.append("Details (key changes):")

    for section in ["modified", "removed", "added"]:
        items = report["details"][section]
        lines.append(f"{section.upper()} ({len(items)}):")
        if items:
            for item in items:
                lines.append(f"  - {item}")
        else:
            lines.append("  - None")
        lines.append("")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def main():
    parser = argparse.ArgumentParser(description="FolderGuard: File Integrity Monitor (SHA-256)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create a manifest baseline from a folder")
    p_init.add_argument("--folder", required=True, help="Folder to scan")
    p_init.add_argument("--out", default="manifest.json", help="Output manifest path")

    p_verify = sub.add_parser("verify", help="Verify folder against baseline manifest.json")
    p_verify.add_argument("--folder", required=True, help="Folder to verify")
    p_verify.add_argument("--manifest", required=True, help="Path to manifest.json")
    p_verify.add_argument("--out", default="output/report.txt", help="Output report text path")
    p_verify.add_argument("--json", default="output/report.json", help="Output report json path")

    args = parser.parse_args()

    if args.cmd == "init":
        m = scan_folder(args.folder)
        save_manifest(m, args.out, args.folder)
        print(f"[OK] Baseline manifest created: {args.out}")

    elif args.cmd == "verify":
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        os.makedirs(os.path.dirname(args.json), exist_ok=True)

        r = verify(args.folder, args.manifest)
        write_report(r, args.out)

        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2)

        print(f"[OK] Report written: {args.out}")
        print(f"[OK] JSON written: {args.json}")
        print(f"[INFO] Risk level: {r['risk_level']}")

if __name__ == "__main__":
    main()
