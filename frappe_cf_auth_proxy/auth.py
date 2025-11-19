import os
import sys
import frappe
from frappe.auth import LoginManager


# ─────────────────────────────────────────────
#   CONFIG VIA ENV VARIABLES
# ─────────────────────────────────────────────

def env_list(key, default_list=None):
    """Return comma-separated ENV var as a clean, lowercased list."""
    raw = os.getenv(key)
    if not raw:
        return [v.lower() for v in (default_list or [])]
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


ALLOWED_DOMAINS = env_list("CF_ALLOWED_DOMAINS")
ADMIN_EMAILS    = env_list("CF_ADMIN_EMAILS")

ADMIN_ROLE      = os.getenv("CF_ADMIN_ROLE", "System Manager")
DEFAULT_ROLE    = os.getenv("CF_DEFAULT_ROLE", "System User")


# ─────────────────────────────────────────────
#   MAIN HOOK
# ─────────────────────────────────────────────

def ensure_user():
    """
    Runs before every request.

    If x-erp-user-email is present (injected by cf-auth-proxy),
    ensure that user exists and log them in using login_as().
    """

    email = frappe.get_request_header("x-erp-user-email")
    print(f"[cloudflare_auth] x-erp-user-email={email!r}", file=sys.stderr, flush=True)

    # No header → normal ERPNext auth (localhost:8080, health checks, etc.)
    if not email:
        return

    email = email.strip().lower()

    # Enforce allowed domains
    if not any(email.endswith("@" + d) for d in ALLOWED_DOMAINS):
        print(
            f"[cloudflare_auth] rejecting unauthorized domain for email={email}",
            file=sys.stderr,
            flush=True,
        )
        return

    # If already logged in, don't override the session
    if frappe.session.user and frappe.session.user != "Guest":
        print(
            f"[cloudflare_auth] session already has user={frappe.session.user}, skipping",
            file=sys.stderr,
            flush=True,
        )
        return

    # Ensure User exists
    user_name = frappe.db.get_value("User", {"email": email}, "name")

    if not user_name:
        first_name = email.split("@")[0]

        print(
            f"[cloudflare_auth] creating new User for email={email}",
            file=sys.stderr,
            flush=True,
        )

        user_doc = frappe.get_doc(
            {
                "doctype": "User",
                "email": email,
                "first_name": first_name,
                "send_welcome_email": 0,
                "enabled": 1,
            }
        )
        user_doc.insert(ignore_permissions=True)
        user_name = user_doc.name

        # Assign roles based on env vars, if roles exist
        roles_to_add = []

        if email in ADMIN_EMAILS and frappe.db.exists("Role", ADMIN_ROLE):
            roles_to_add.append(ADMIN_ROLE)

        if frappe.db.exists("Role", DEFAULT_ROLE) and DEFAULT_ROLE not in roles_to_add:
            roles_to_add.append(DEFAULT_ROLE)

        for role in roles_to_add:
            print(
                f"[cloudflare_auth] adding role={role} to user={user_name}",
                file=sys.stderr,
                flush=True,
            )
            user_doc.add_roles(role)

    # Log in via login_as (canonical way)
    if not hasattr(frappe.local, "login_manager"):
        frappe.local.login_manager = LoginManager()

    frappe.local.login_manager.login_as(user_name)

    print(
        f"[cloudflare_auth] login_as done for user={user_name} (email={email})",
        file=sys.stderr,
        flush=True,
    )
