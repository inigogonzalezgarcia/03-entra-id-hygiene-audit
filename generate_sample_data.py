"""Generate a synthetic Entra ID user export for demos and tests.

Same fields as scripts/Export-EntraUsers.ps1 produces. All people are fictional.
"""

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

FIRST = ["alex", "maria", "jon", "laura", "david", "sara", "pablo", "elena",
         "marco", "julia", "omar", "ines", "lucas", "nora", "hugo", "clara"]
LAST = ["garcia", "rossi", "martin", "dubois", "smith", "yilmaz", "silva",
        "jansen", "lopez", "moreau", "bianchi", "kaya", "novak", "fischer"]
DEPARTMENTS = ["Finance", "Operations", "Sales", "IT", "HR", "Legal"]
DOMAIN = "contoso-demo.com"
PARTNERS = ["partner-demo.com", "vendor-demo.net", "agency-demo.org"]


def generate_users(count: int = 220, seed: int = 11, as_of: datetime | None = None) -> list[dict]:
    """Return fictional users in the shape of the export script."""
    rng = random.Random(seed)
    as_of = as_of or datetime.now(timezone.utc)
    users = []

    for i in range(count):
        guest = rng.random() < 0.18
        first, last = rng.choice(FIRST), rng.choice(LAST)
        created = as_of - timedelta(days=rng.randint(5, 1500))

        # Sign-in pattern: most users are active, some drift away, a few never sign in.
        roll = rng.random()
        if roll < (0.30 if guest else 0.08):
            last_sign_in = None
        elif roll < (0.60 if guest else 0.18):
            last_sign_in = as_of - timedelta(days=rng.randint(91, 500))
        else:
            last_sign_in = as_of - timedelta(days=rng.randint(0, 30), hours=rng.randint(0, 23))
        if last_sign_in and last_sign_in < created:
            last_sign_in = created + timedelta(days=1)

        is_admin = not guest and rng.random() < 0.05
        mfa = rng.random() < (0.85 if is_admin else 0.45 if guest else 0.88)

        if guest:
            upn = f"{first}.{last}_{rng.choice(PARTNERS).replace('.', '_')}#EXT#@{DOMAIN}"
        else:
            upn = f"{first}.{last}{i}@{DOMAIN}"

        users.append({
            "id": f"demo-user-{i:05d}",
            "displayName": f"{first.title()} {last.title()}" + (" (Guest)" if guest else ""),
            "userPrincipalName": upn,
            "userType": "Guest" if guest else "Member",
            "accountEnabled": rng.random() > 0.06,
            "department": None if guest else rng.choice(DEPARTMENTS),
            "createdDateTime": created.isoformat(),
            "lastSignInDateTime": last_sign_in.isoformat() if last_sign_in else None,
            "isMfaRegistered": mfa,
            "isAdmin": is_admin,
        })
    return users


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic Entra ID user export.")
    parser.add_argument("--count", type=int, default=220, help="number of users (default: 220)")
    parser.add_argument("--seed", type=int, default=11, help="random seed for repeatable data")
    parser.add_argument("--output", default="sample_data/entra_users.json", help="output JSON path")
    args = parser.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(generate_users(args.count, args.seed), indent=2), encoding="utf-8")
    print(f"Wrote {args.count} fictional users to {out}")


if __name__ == "__main__":
    main()
