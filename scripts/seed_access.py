"""Idempotently create the least-privilege Catalyst Center roles and users (roadmap D17).

    uv run python scripts/seed_access.py  # create/update roles, access groups, users
    uv run python scripts/seed_access.py --check    # show what differs, change nothing
    uv run python scripts/seed_access.py --delete   # remove the users and roles again

Runs as the admin in .env (CATC_USERNAME / CATC_PASSWORD, needs SUPER-ADMIN). The users and their
passwords come from .env as well:

    CATC_RO_USERNAME / CATC_RO_PASSWORD        role mcp-catc-ro         (read tier, live least-privilege test)
    CATC_RW_USERNAME / CATC_RW_PASSWORD        role mcp-catc-rw         (read + write tiers; hosted container)
    CATC_ADMIN_USERNAME / CATC_ADMIN_PASSWORD  role mcp-catc-dangerous  (every tier)

Role definitions live in src/catc_mcp/rbac.py (ROLES); docs/least-privilege.md explains every permission.
Permissions not
listed in a role are set to Deny (when the permission allows Deny) so the role never silently widens when a
Catalyst Center upgrade adds a new permission with a Read default. Passwords are never printed. A user that
exists keeps its password (Catalyst Center's user PUT can't change it); delete it with --delete to reset.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import httpx
from dotenv import dotenv_values

from catc_mcp.rbac import ROLES  # role definitions (docs/least-privilege.md)

ROOT = Path(__file__).resolve().parent.parent

USERS = [("CATC_RO_", "mcp-catc-ro"), ("CATC_RW_", "mcp-catc-rw"), ("CATC_ADMIN_", "mcp-catc-dangerous")]


def group_name(role: str) -> str:
    return f"{role}_GLOBAL"


def env() -> dict[str, str]:
    values = {k: v for k, v in dotenv_values(ROOT / ".env").items() if v is not None}
    return {**values, **{k: v for k, v in os.environ.items() if k.startswith("CATC_")}}


class Catc:
    def __init__(self, e: dict[str, str]) -> None:
        verify = e.get("CATC_VERIFY_SSL", "true").lower() not in ("0", "false", "no")
        self.base = e["CATC_URL"].rstrip("/")
        self.http = httpx.Client(verify=verify, timeout=60)
        r = self.http.post(
            self.base + "/dna/system/api/v1/auth/token", auth=(e["CATC_USERNAME"], e["CATC_PASSWORD"])
        )
        r.raise_for_status()
        self.http.headers["X-Auth-Token"] = r.json()["Token"]

    def call(self, method: str, path: str, body: Any = None) -> Any:
        r = self.http.request(method, self.base + path, json=body)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path} -> HTTP {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else None


def role_body(
    catalog: list[dict[str, Any]], name: str, description: str, wanted: dict[str, str]
) -> dict[str, Any]:
    """Every leaf permission explicitly: the wanted privilege, else Deny (or the minimum where Deny isn't
    allowed)."""
    order = {"Deny": 0, "Read": 1, "Write": 2}
    perms = []
    for p in catalog:
        pid = p["id"]
        if "." not in pid:
            continue
        priv = wanted.get(pid, "Deny")
        lo, hi = p.get("minimumPrivilege", "Deny"), p.get("maximumPrivilege", "Write")
        if order[priv] < order[lo]:
            priv = lo
        if order[priv] > order[hi]:
            priv = hi
        perms.append({"id": pid, "privilege": priv})
    unknown = sorted(set(wanted) - {p["id"] for p in catalog})
    if unknown:
        print(f"  note: {name}: permissions not on this Catalyst Center (ignored): {', '.join(unknown)}")
    return {"name": name, "description": description, "permissions": perms}


def diff(current: dict[str, Any], body: dict[str, Any]) -> list[str]:
    have = {p["id"]: p["privilege"] for p in current.get("permissions", [])}
    return [
        f"{p['id']}: {have.get(p['id'], 'Deny')} -> {p['privilege']}"
        for p in body["permissions"]
        if have.get(p["id"], "Deny") != p["privilege"]  # Catalyst Center omits Deny entries
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="show differences only")
    ap.add_argument("--delete", action="store_true", help="remove the users, access groups and roles")
    a = ap.parse_args()
    e = env()
    c = Catc(e)
    roles = {r["name"]: r for r in c.call("GET", "/dna/system/api/v2/roles")["response"]}
    users = {u["username"]: u for u in c.call("GET", "/dna/system/api/v1/user")["response"]["users"]}

    if a.delete:
        for prefix, _ in USERS:
            name = e.get(prefix + "USERNAME")
            if name and name in users:
                c.call("DELETE", f"/dna/system/api/v1/user/{users[name]['userId']}")
                print(f"  user {name} removed")
        groups = c.call("GET", "/dna/system/api/v1/accessGroups")["response"]
        for g in groups:
            if g["accessGroupInfo"]["name"] in {group_name(r) for r in ROLES}:
                c.call("DELETE", f"/dna/system/api/v1/accessGroups/{g['id']}")
                print(f"  access group {g['accessGroupInfo']['name']} removed")
        for name in ROLES:
            if name in roles:
                c.call("DELETE", f"/dna/system/api/v2/roles/{roles[name]['id']}")
                print(f"  role {name} removed")
        return 0

    catalog = c.call("GET", "/dna/system/api/v2/roles/permissions")["response"]
    for name, (description, wanted) in ROLES.items():
        body = role_body(catalog, name, description, wanted)
        if name not in roles:
            print(
                f"role {name}: create ({sum(p['privilege'] != 'Deny' for p in body['permissions'])} granted)"
            )
            if not a.check:
                c.call("POST", "/dna/system/api/v2/roles", body)
            continue
        current = c.call("GET", f"/dna/system/api/v2/roles/{roles[name]['id']}")
        current = current.get("response", current)  # this GET has no "response" envelope
        changes = diff(current, body)
        print(f"role {name}: {'up to date' if not changes else f'{len(changes)} change(s)'}")
        for line in changes:
            print(f"  {line}")
        if changes and not a.check:
            c.call("PUT", f"/dna/system/api/v2/roles/{roles[name]['id']}", body)

    # Access groups: a user needs one that binds its role to a scope (here: Global). Users created through the
    # API without one get accessGroups [""], log in fine, but some writes fail inside Catalyst Center
    # (tag creation: "Failed to add members based on the rules. java.lang.NullPointerException").
    groups = {
        g["accessGroupInfo"]["name"]: g for g in c.call("GET", "/dna/system/api/v1/accessGroups")["response"]
    }
    for role in ROLES:
        gname = group_name(role)
        if gname in groups:
            print(f"access group {gname}: up to date")
            continue
        print(f"access group {gname}: create (role {role}, scope Global)")
        if not a.check:
            made = c.call(
                "POST",
                "/dna/system/api/v1/accessGroups",
                {
                    "name": gname,
                    "description": f"Global access for role {role}. Managed by scripts/seed_access.py.",
                    "role": [role],
                    "resourceGroups": [{"name": "Global", "srcResourceId": "*", "type": "site"}],
                },
            )
            groups[gname] = made

    for prefix, role in USERS:
        name, password = e.get(prefix + "USERNAME"), e.get(prefix + "PASSWORD")
        if not name or not password:
            print(f"user ({prefix}USERNAME): not configured in .env, skipped")
            continue
        group_id = groups.get(group_name(role), {}).get("id", "")
        want = {"roleList": [role], "accessGroups": [group_id]}
        if name in users:
            have = {k: users[name].get(k) for k in want}
            if have != want:
                print(f"user {name}: {have} -> {want}")
                if not a.check:
                    c.call(
                        "PUT",
                        "/dna/system/api/v1/user",
                        {
                            "userId": users[name]["userId"],
                            "username": name,
                            "firstName": "mcp",
                            "lastName": role,
                            **want,
                        },
                    )
            else:
                print(f"user {name}: up to date ({role})")
            continue
        print(f"user {name}: create with role {role}")
        if not a.check:
            c.call(
                "POST",
                "/dna/system/api/v1/user",
                {"username": name, "password": password, "firstName": "mcp", "lastName": role, **want},
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
