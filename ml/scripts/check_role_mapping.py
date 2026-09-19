import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
ldap = pd.read_csv(DATA_DIR / "ldap.csv")
print("Total users:", len(ldap))
print("\nUnique roles (value counts):")
print(ldap['role'].value_counts())

print("\nUnique functional_unit (value counts):")
print(ldap['functional_unit'].value_counts())

print("\nUnique department (value counts):")
print(ldap['department'].value_counts())

# look for anything security-related anywhere
mask = (
    ldap['role'].str.contains('Security', case=False, na=False) |
    ldap['functional_unit'].str.contains('Security', case=False, na=False) |
    ldap['department'].str.contains('Security', case=False, na=False) |
    ldap['team'].astype(str).str.contains('Security', case=False, na=False) |
    ldap['business_unit'].astype(str).str.contains('Security', case=False, na=False)
)
print("\nRows matching 'Security' anywhere:", mask.sum())
print(ldap[mask].head(10))

print("\nITAdmin count:", (ldap['role'] == 'ITAdmin').sum())

# file.csv extension check
file_df = pd.read_csv(DATA_DIR / "file.csv", usecols=['filename'])
exts = file_df['filename'].str.extract(r'\.([A-Za-z0-9]+)$')[0].str.lower()
print("\nfile.csv extension counts:")
print(exts.value_counts())
