"""Audit identity hygiene from an Entra ID user export.

Flags enabled accounts that weaken security: admins and members without MFA,
members who stopped signing in, and guests nobody uses any more.

Input: JSON produced by scripts/Export-EntraUsers.ps1 or generate_sample_data.py.
Output: a self-contained HTML report and a CSV action list.

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Issue keys, most urgent first. Order drives sorting in the action list.
ISSUES = {
    "admin_no_mfa": "Admin without MFA",
    "no_mfa": "No MFA registered",
    "inactive_member": "Inactive member",
    "stale_guest": "Stale guest",
}
ISSUE_RANK = {key: rank for rank, key in enumerate(ISSUES)}
# status role + icon per issue, so colour never carries meaning alone
ISSUE_STYLE = {
    "admin_no_mfa": ("critical", "&#10005;"),
    "no_mfa": ("critical", "&#10005;"),
    "inactive_member": ("serious", "!"),
    "stale_guest": ("serious", "!"),
}


@dataclass
class Finding:
    user: dict
    issues: list[str]
    days_since_sign_in: int | None


@dataclass
class Summary:
    as_of: datetime
    inactive_days: int
    total: int = 0
    members: int = 0
    guests: int = 0
    disabled: int = 0
    members_with_mfa: int = 0
    enabled_members: int = 0
    counts: Counter = field(default_factory=Counter)
    by_department: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    @property
    def mfa_rate(self) -> float:
        return self.members_with_mfa / self.enabled_members * 100 if self.enabled_members else 0.0


def load_users(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        data = data.get("value", [data])
    if not isinstance(data, list):
        raise ValueError("Expected a list of users.")
    return data


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def user_issues(user: dict, as_of: datetime, inactive_days: int) -> tuple[list[str], int | None]:
    """Return the issue keys for one user, and days since their last sign-in."""
    last = _parse_dt(user.get("lastSignInDateTime"))
    days = max(0, (as_of - last).days) if last else None
    if user.get("accountEnabled") is False:
        return [], days  # disabled accounts cannot sign in; they are counted, not flagged

    created = _parse_dt(user.get("createdDateTime"))
    account_age = (as_of - created).days if created else None
    # "Never signed in" only counts once the account is older than the threshold.
    idle = (days is not None and days > inactive_days) or (
        days is None and (account_age is None or account_age > inactive_days))

    issues = []
    is_guest = str(user.get("userType", "Member")).lower() == "guest"
    if is_guest:
        if idle:
            issues.append("stale_guest")
    else:
        if user.get("isMfaRegistered") is False:
            issues.append("admin_no_mfa" if user.get("isAdmin") else "no_mfa")
        if idle:
            issues.append("inactive_member")
    return issues, days


def audit(users: list[dict], as_of: datetime | None = None, inactive_days: int = 90) -> Summary:
    as_of = as_of or datetime.now(timezone.utc)
    s = Summary(as_of=as_of, inactive_days=inactive_days, total=len(users))
    depts: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # [enabled members, with MFA]

    for user in users:
        is_guest = str(user.get("userType", "Member")).lower() == "guest"
        s.guests += is_guest
        s.members += not is_guest
        if user.get("accountEnabled") is False:
            s.disabled += 1
        elif not is_guest:
            s.enabled_members += 1
            dept = user.get("department") or "(none)"
            depts[dept][0] += 1
            if user.get("isMfaRegistered"):
                s.members_with_mfa += 1
                depts[dept][1] += 1

        issues, days = user_issues(user, as_of, inactive_days)
        s.counts.update(issues)
        if issues:
            s.findings.append(Finding(user, issues, days))

    s.by_department = dict(sorted(depts.items(), key=lambda kv: kv[1][1] / kv[1][0] if kv[1][0] else 0))
    s.findings.sort(key=lambda f: (ISSUE_RANK[f.issues[0]], -(f.days_since_sign_in or 10**6)))
    return s


def write_action_csv(s: Summary, path: str | Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["displayName", "userPrincipalName", "userType", "department", "isAdmin",
                    "isMfaRegistered", "daysSinceLastSignIn", "issues"])
        for f in s.findings:
            u = f.user
            w.writerow([u.get("displayName"), u.get("userPrincipalName"), u.get("userType"),
                        u.get("department"), u.get("isAdmin"), u.get("isMfaRegistered"),
                        "never" if f.days_since_sign_in is None else f.days_since_sign_in,
                        "; ".join(ISSUES[i] for i in f.issues)])


# --------------------------------------------------------------------------- HTML

CSS = """
:root{--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;
--grid:#e1e0d9;--border:rgba(11,11,11,.10);--bar:#2a78d6;
--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b}
@media (prefers-color-scheme:dark){:root{--page:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;
--grid:#2c2c2a;--border:rgba(255,255,255,.10);--bar:#3987e5}}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 12px}
.meta{color:var(--ink2);margin:0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:24px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.tile .label{color:var(--ink2);font-size:13px}.tile .value{font-size:28px;font-weight:600;font-variant-numeric:tabular-nums}
.tile .note{color:var(--muted);font-size:12px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:4px 16px;overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--grid);white-space:nowrap}
th.num{text-align:right}
th{color:var(--ink2);font-weight:500;font-size:13px}tr:last-child td{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.bar{height:8px;background:var(--grid);border-radius:4px;min-width:120px}
.bar span{display:block;height:8px;background:var(--bar);border-radius:4px}
.badge{display:inline-flex;align-items:center;gap:4px;margin:0 6px 2px 0;font-size:12px;color:var(--ink)}
.badge i{width:8px;height:8px;border-radius:50%;display:inline-block}
.critical i{background:var(--critical)}.serious i{background:var(--serious)}.warning i{background:var(--warning)}
.badge b{font-weight:600}
footer{color:var(--muted);font-size:12px;margin-top:32px}
"""


def _badge(issue: str) -> str:
    role, icon = ISSUE_STYLE[issue]
    return f'<span class="badge {role}"><i></i><b>{icon}</b>{ISSUES[issue]}</span>'


def render_html(s: Summary, title: str = "Identity Hygiene Audit") -> str:
    e = html.escape
    tiles = [
        ("Accounts", f"{s.total:,}", f"{s.members:,} members, {s.guests:,} guests"),
        ("MFA registration", f"{s.mfa_rate:.1f}%", "enabled members"),
        ("Admins without MFA", f"{s.counts['admin_no_mfa']:,}", "fix first"),
        ("Inactive members", f"{s.counts['inactive_member']:,}", f"no sign-in for {s.inactive_days}+ days"),
        ("Stale guests", f"{s.counts['stale_guest']:,}", f"no sign-in for {s.inactive_days}+ days"),
    ]
    tiles_html = "".join(
        f'<div class="tile"><div class="label">{e(l)}</div><div class="value">{v}</div>'
        f'<div class="note">{e(n)}</div></div>' for l, v, n in tiles)

    dept_rows = []
    for dept, (total, mfa) in s.by_department.items():
        pct = mfa / total * 100 if total else 0
        dept_rows.append(
            f"<tr><td>{e(dept)}</td><td class='num'>{total}</td><td class='num'>{mfa}</td>"
            f"<td class='num'>{pct:.1f}%</td><td title='{e(dept)}: {pct:.1f}% with MFA'>"
            f"<div class='bar'><span style='width:{pct:.1f}%'></span></div></td></tr>")

    rows = []
    for f in s.findings:
        u = f.user
        days = "never" if f.days_since_sign_in is None else f"{f.days_since_sign_in} d"
        rows.append(
            f"<tr><td>{e(str(u.get('displayName', '')))}</td><td>{e(str(u.get('userPrincipalName', '')))}</td>"
            f"<td>{e(str(u.get('userType', '')))}</td><td class='num'>{days}</td>"
            f"<td>{''.join(_badge(i) for i in f.issues)}</td></tr>")
    if not rows:
        rows.append("<tr><td colspan='5'>No accounts need action.</td></tr>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head>
<body><main>
<h1>{e(title)}</h1>
<p class="meta">Data as of {s.as_of:%d %b %Y %H:%M} UTC &middot; inactivity threshold {s.inactive_days} days
&middot; {s.disabled} disabled accounts excluded</p>
<section class="tiles">{tiles_html}</section>
<h2>MFA registration by department</h2>
<div class="card"><table><thead><tr><th>Department</th><th class='num'>Members</th><th class='num'>With MFA</th>
<th class='num'>Rate</th><th></th></tr></thead><tbody>{''.join(dept_rows)}</tbody></table></div>
<h2>Accounts that need action ({len(s.findings)})</h2>
<div class="card"><table><thead><tr><th>Name</th><th>User principal name</th><th>Type</th>
<th class='num'>Last sign-in</th><th>Issues</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<footer>Generated by entra-id-hygiene-audit.</footer>
</main></body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit identity hygiene from an Entra ID user export.")
    parser.add_argument("input", help="JSON export of users")
    parser.add_argument("--out-dir", default="output", help="folder for report.html and action_list.csv")
    parser.add_argument("--inactive-days", type=int, default=90, help="days without sign-in before flagging")
    parser.add_argument("--title", default="Identity Hygiene Audit", help="report title")
    args = parser.parse_args()

    s = audit(load_users(args.input), inactive_days=args.inactive_days)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(render_html(s, args.title), encoding="utf-8")
    write_action_csv(s, out / "action_list.csv")
    print(f"{s.total} accounts, MFA {s.mfa_rate:.1f}% of enabled members, {len(s.findings)} need action.")
    print(f"Report: {out / 'report.html'}\nAction list: {out / 'action_list.csv'}")


if __name__ == "__main__":
    main()
