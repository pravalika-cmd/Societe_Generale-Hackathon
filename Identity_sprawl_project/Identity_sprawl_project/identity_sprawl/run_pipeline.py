import subprocess
import sys

scripts = [
    "gen_01_master_identities.py",
    "gen_02_platform_snapshots.py",
    "gen_03_group_mappings.py",
    "gen_04_audit_events.py",
    "gen_05_offboarding.py",
    "gen_06_correlate.py",
]

for script in scripts:
    print(f"\n> Running {script}...")
    result = subprocess.run([sys.executable, script], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(f" Error in {script}:")
        print(result.stderr)
        break
else:
    print("\n All data generated successfully.")
    print(" Check the data/ folder for all CSVs.")