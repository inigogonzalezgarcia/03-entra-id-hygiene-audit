import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from generate_sample_data import generate_users  # noqa: E402
from identity_audit import audit, render_html, user_issues  # noqa: E402

AS_OF = datetime(2026, 10, 1, tzinfo=timezone.utc)


def user(**overrides):
    base = {
        "displayName": "Demo User",
        "userPrincipalName": "demo.user@contoso-demo.com",
        "userType": "Member",
        "accountEnabled": True,
        "department": "IT",
        "createdDateTime": (AS_OF - timedelta(days=400)).isoformat(),
        "lastSignInDateTime": (AS_OF - timedelta(days=2)).isoformat(),
        "isMfaRegistered": True,
        "isAdmin": False,
    }
    base.update(overrides)
    return base


def test_healthy_member_has_no_issues():
    assert user_issues(user(), AS_OF, 90) == ([], 2)


def test_admin_without_mfa_is_flagged_as_admin():
    issues, _ = user_issues(user(isAdmin=True, isMfaRegistered=False), AS_OF, 90)
    assert issues == ["admin_no_mfa"]


def test_inactive_member_without_mfa():
    old = (AS_OF - timedelta(days=200)).isoformat()
    issues, days = user_issues(user(isMfaRegistered=False, lastSignInDateTime=old), AS_OF, 90)
    assert issues == ["no_mfa", "inactive_member"] and days == 200


def test_new_account_that_never_signed_in_is_not_flagged_yet():
    new = user(createdDateTime=(AS_OF - timedelta(days=10)).isoformat(), lastSignInDateTime=None)
    assert user_issues(new, AS_OF, 90) == ([], None)


def test_old_guest_that_never_signed_in_is_stale():
    guest = user(userType="Guest", lastSignInDateTime=None, isMfaRegistered=False)
    assert user_issues(guest, AS_OF, 90) == (["stale_guest"], None)


def test_disabled_accounts_are_counted_not_flagged():
    s = audit([user(accountEnabled=False, isMfaRegistered=False), user()], as_of=AS_OF)
    assert s.disabled == 1 and s.findings == [] and s.mfa_rate == 100.0


def test_sample_data_renders_report():
    users = generate_users(count=60, seed=3, as_of=AS_OF)
    s = audit(users, as_of=AS_OF)
    assert s.total == 60 and s.members + s.guests == 60
    assert "Identity Hygiene Audit" in render_html(s)
