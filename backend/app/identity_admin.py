"""Local identity administration CLI.

The client-mode server rejects the legacy shared key and requires an active
persisted per-user credential, so the FIRST client administrator must be
provisioned out-of-band. This CLI is that bounded, explicit path: it runs
locally against the configured state (it never opens a network route), operates
only through validated store methods, returns a raw token exactly once, and
persists only the token hash + fingerprint. It never embeds a default
credential and never auto-provisions.

Usage:

    python -m backend.app.identity_admin list-users
    python -m backend.app.identity_admin list-credentials
    python -m backend.app.identity_admin create-user \
        --email admin@client.example --full-name "Client Admin" \
        --role admin --confirm-tenant <tenant-slug> --yes
    python -m backend.app.identity_admin create-credential \
        --user-id <uuid> --confirm-tenant <tenant-slug> --yes
    python -m backend.app.identity_admin revoke-credential \
        --credential-id <uuid> --yes

`--confirm-tenant` must match the configured runtime tenant slug, guarding
against accidental operation against an unexpected tenant/state path. A
mutating command requires either an interactive confirmation (re-typing the
tenant slug) or the non-interactive CI-safe `--yes` flag.
"""
from __future__ import annotations

import argparse
import sys
from uuid import UUID


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.app.identity_admin",
        description="Local, offline identity/credential administration for client mode.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-users", help="List provisioned users (no secrets).")
    sub.add_parser("list-credentials", help="List credentials (fingerprints/status only).")

    create_user = sub.add_parser("create-user", help="Create a non-bootstrap persisted user.")
    create_user.add_argument("--email", required=True)
    create_user.add_argument("--full-name", required=True)
    create_user.add_argument(
        "--role",
        action="append",
        required=True,
        help="Role to assign; repeat for multiple. Existing roles only.",
    )
    _add_confirmation_flags(create_user)

    create_cred = sub.add_parser("create-credential", help="Create a credential for a user (token shown once).")
    create_cred.add_argument("--user-id", required=True)
    _add_confirmation_flags(create_cred)

    revoke = sub.add_parser("revoke-credential", help="Revoke a credential immediately.")
    revoke.add_argument("--credential-id", required=True)
    _add_confirmation_flags(revoke)

    return parser


def _add_confirmation_flags(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "--confirm-tenant",
        help="Must equal the configured runtime tenant slug; refuses on mismatch.",
    )
    sub.add_argument(
        "--yes",
        action="store_true",
        help="Non-interactive CI-safe confirmation (skips the interactive prompt).",
    )


def _confirm(store, args, action: str) -> bool:
    """Fail-closed confirmation: prints the target, enforces --confirm-tenant, and
    requires --yes (non-interactive) or a matching interactive re-type."""
    tenant_slug = store.tenant.slug
    print(f"Target tenant : {tenant_slug}")
    print(f"State path    : {store.state_path}")
    print(f"Action        : {action}")
    if args.confirm_tenant is not None and args.confirm_tenant != tenant_slug:
        print(
            f"ABORT: --confirm-tenant {args.confirm_tenant!r} does not match the "
            f"configured tenant {tenant_slug!r}.",
            file=sys.stderr,
        )
        return False
    if args.yes:
        return True
    if not sys.stdin.isatty():
        print(
            "ABORT: refusing to mutate non-interactively without --yes.",
            file=sys.stderr,
        )
        return False
    typed = input(f"Type the tenant slug ({tenant_slug!r}) to proceed: ").strip()
    if typed != tenant_slug:
        print("ABORT: confirmation did not match.", file=sys.stderr)
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    from .schemas import Role
    from .store import create_store

    args = _build_parser().parse_args(argv)
    store = create_store()

    if args.command == "list-users":
        for user in store.list_users():
            print(
                f"{user.id} | {user.email} | roles={[r.value for r in user.roles]} | "
                f"status={user.account_status} | bootstrap={user.is_bootstrap}"
            )
        return 0

    if args.command == "list-credentials":
        for cred in store.list_credentials():
            print(
                f"{cred.credential_id} | user={cred.user_id} | fp={cred.token_fingerprint} | "
                f"status={cred.status} | source={cred.authentication_source}"
            )
        return 0

    if args.command == "create-user":
        try:
            roles = [Role(role) for role in args.role]
        except ValueError as exc:
            print(f"ABORT: unknown role: {exc}", file=sys.stderr)
            return 2
        if not _confirm(store, args, f"create-user {args.email} roles={[r.value for r in roles]}"):
            return 2
        try:
            user = store.create_user(args.email, args.full_name, roles)
        except ValueError as exc:
            print(f"ABORT: {exc}", file=sys.stderr)
            return 2
        print(f"CREATED user_id={user.id} email={user.email} roles={[r.value for r in user.roles]}")
        return 0

    if args.command == "create-credential":
        try:
            user_id = UUID(args.user_id)
        except ValueError:
            print("ABORT: --user-id is not a valid UUID.", file=sys.stderr)
            return 2
        if not _confirm(store, args, f"create-credential for user {user_id}"):
            return 2
        try:
            credential, raw_token = store.create_credential(user_id)
        except KeyError:
            print("ABORT: unknown user.", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"ABORT: {exc}", file=sys.stderr)
            return 2
        print(f"CREATED credential_id={credential.credential_id} fingerprint={credential.token_fingerprint}")
        print("Store this token now; it is shown once and cannot be retrieved again:")
        print(f"TOKEN {raw_token}")
        return 0

    if args.command == "revoke-credential":
        try:
            credential_id = UUID(args.credential_id)
        except ValueError:
            print("ABORT: --credential-id is not a valid UUID.", file=sys.stderr)
            return 2
        if not _confirm(store, args, f"revoke-credential {credential_id}"):
            return 2
        try:
            credential = store.revoke_credential(credential_id)
        except KeyError:
            print("ABORT: unknown credential.", file=sys.stderr)
            return 2
        print(f"REVOKED credential_id={credential.credential_id} status={credential.status}")
        return 0

    return 2


if __name__ == "__main__":
    from .audit_keys import AuditIntegrityUnavailable

    try:
        sys.exit(main())
    except AuditIntegrityUnavailable as exc:
        # Client-mode fail-closed (MC1/MC2): no valid active audit key, so the CLI
        # refuses to provision/revoke BEFORE mutating identity state. No key
        # material is included in the message.
        print(f"ABORT: {exc}", file=sys.stderr)
        sys.exit(1)
