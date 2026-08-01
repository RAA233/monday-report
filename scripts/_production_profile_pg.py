"""Disposable TLS-enabled PostgreSQL provisioning for the production-PROFILE behavioral
tier. Everything here is EPHEMERAL and DISPOSABLE — a runner-owned Docker container, a
disposable self-signed CA, disposable server certs, and disposable roles/passwords. It
connects to NOTHING real and reads no real credential.

Provides a context manager ``disposable_tls_stack()`` that yields a dict describing the
live stack (verify-full DSN, CA path, migration + runtime role names) and tears it all
down on exit. Reused by every production-profile guard so provisioning lives in one
place.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

IMAGE = "pgvector/pgvector:pg16"
_CONTAINER_UID = "999"  # postgres uid in the debian image


def _run(args: list[str], *, timeout: int = 120, check: bool = True,
         input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, timeout=timeout, input=input_bytes)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(args[:2])} :: "
                           f"{proc.stderr.decode('utf-8','replace')[:300]}")
    return proc


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _openssl(certdir: Path, host_cn: str) -> None:
    """Generate a disposable self-signed CA and a server cert signed by it, with the
    server cert's SAN matching ``host_cn`` so verify-full's hostname check passes."""
    ca_key = certdir / "ca.key"
    ca_crt = certdir / "ca.crt"
    srv_key = certdir / "server.key"
    srv_csr = certdir / "server.csr"
    srv_crt = certdir / "server.crt"
    ext = certdir / "san.ext"
    ext.write_text(f"subjectAltName=DNS:{host_cn}\nbasicConstraints=CA:FALSE\n"
                   "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    _run(["openssl", "genrsa", "-out", str(ca_key), "2048"])
    _run(["openssl", "req", "-x509", "-new", "-nodes", "-key", str(ca_key), "-sha256",
          "-days", "2", "-subj", "/CN=disposable-profile-ca", "-out", str(ca_crt)])
    _run(["openssl", "genrsa", "-out", str(srv_key), "2048"])
    _run(["openssl", "req", "-new", "-key", str(srv_key), "-subj", f"/CN={host_cn}",
          "-out", str(srv_csr)])
    _run(["openssl", "x509", "-req", "-in", str(srv_csr), "-CA", str(ca_crt), "-CAkey",
          str(ca_key), "-CAcreateserial", "-days", "2", "-sha256", "-extfile", str(ext),
          "-out", str(srv_crt)])


@contextlib.contextmanager
def disposable_tls_stack(*, apply_migrations: bool = True) -> Iterator[dict]:
    """Provision a disposable pgvector container with verify-full TLS, a migration
    superuser login role, and a restricted runtime login role (nosuperuser,
    nobypassrls). Applies migrations 0001-0007 as the migration role. Yields a dict;
    tears everything down on exit."""
    run_hash = secrets.token_hex(6)
    name = f"mr-profile-{run_hash}"
    volume = f"{name}-vol"
    port = _free_port()
    superpw = secrets.token_hex(16)
    rt_role = f"mr_prt_{run_hash}"
    mig_role = f"mr_pmig_{run_hash}"
    rt_pw = secrets.token_hex(16)
    host_cn = "localhost"
    tmp = Path(tempfile.mkdtemp(prefix=f"mrprofile_{run_hash}_"))
    certdir = tmp / "certs"
    certdir.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        _openssl(certdir, host_cn)
        # 1. Start a plain container first (TLS wired in after cert copy).
        _run(["docker", "run", "-d", "--name", name, "-v", f"{volume}:/var/lib/postgresql/data",
              "-e", f"POSTGRES_PASSWORD={superpw}", "-e", "POSTGRES_DB=mrprofile",
              "-p", f"127.0.0.1:{port}:5432", IMAGE], timeout=120)
        created = True
        # 2. Wait for readiness (pg_isready inside the container).
        deadline = time.monotonic() + 60
        while True:
            r = _run(["docker", "exec", name, "pg_isready", "-U", "postgres"], check=False)
            if r.returncode == 0:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("disposable postgres did not become ready")
            time.sleep(0.5)
        # 3. Copy certs in, fix ownership/permissions, enable TLS, reload.
        for fn in ("server.crt", "server.key", "ca.crt"):
            _run(["docker", "cp", str(certdir / fn), f"{name}:/var/lib/postgresql/{fn}"])
        _run(["docker", "exec", "-u", "0", name, "chown", f"{_CONTAINER_UID}:{_CONTAINER_UID}",
              "/var/lib/postgresql/server.crt", "/var/lib/postgresql/server.key",
              "/var/lib/postgresql/ca.crt"])
        _run(["docker", "exec", "-u", "0", name, "chmod", "600",
              "/var/lib/postgresql/server.key"])
        conf_lines = (
            "ssl = on",
            "ssl_cert_file = '/var/lib/postgresql/server.crt'",
            "ssl_key_file = '/var/lib/postgresql/server.key'",
            "ssl_ca_file = '/var/lib/postgresql/ca.crt'",
        )
        conf_script = " && ".join(
            f"echo {line!r} >> /var/lib/postgresql/data/postgresql.conf" for line in conf_lines)
        _run(["docker", "exec", "-u", "0", name, "bash", "-lc", conf_script])
        # Require SSL for host connections: neutralise the image's permissive default
        # `host` lines (first-match-wins would otherwise accept plaintext before our
        # reject), keep local (unix socket) trust for admin exec, then add an SSL-only
        # policy so a plaintext client is rejected by the server too (defense in depth).
        _run(["docker", "exec", "-u", "0", name, "bash", "-lc",
              "sed -i -E 's/^host([^s].*)/# disabled-for-tls host\\1/' "
              "/var/lib/postgresql/data/pg_hba.conf && "
              "echo 'hostnossl all all 0.0.0.0/0 reject' >> "
              "/var/lib/postgresql/data/pg_hba.conf && "
              "echo 'hostssl all all 0.0.0.0/0 scram-sha-256' >> "
              "/var/lib/postgresql/data/pg_hba.conf"])
        _run(["docker", "exec", name, "pg_ctl", "-D", "/var/lib/postgresql/data", "reload"],
             check=False)
        # A reload does not always re-read ssl on older builds; restart to be safe.
        _run(["docker", "restart", name], timeout=60)
        deadline = time.monotonic() + 60
        while True:
            r = _run(["docker", "exec", name, "pg_isready", "-U", "postgres"], check=False)
            if r.returncode == 0:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("disposable postgres did not come back after TLS restart")
            time.sleep(0.5)

        # Forward-slash path: libpq keyword/value DSNs treat backslash as an escape, so a
        # Windows path must be POSIX-style. hostaddr pins the IPv4 loopback (avoiding a slow
        # IPv6 ::1 attempt) while host=localhost drives verify-full's hostname check.
        ca_path = (certdir / "ca.crt").as_posix()
        _addr = "hostaddr=127.0.0.1"
        admin_dsn = (f"host={host_cn} {_addr} port={port} dbname=mrprofile user=postgres "
                     f"password={superpw} sslmode=verify-full sslrootcert={ca_path}")
        # 4. Roles: a migration login (superuser, needed for `create extension vector`
        #    and 0007's `alter role`), and a restricted runtime login.
        import psycopg
        with psycopg.connect(admin_dsn, autocommit=True) as c:
            with c.cursor() as cur:
                cur.execute(f"create role {mig_role} login superuser password '{superpw}'")
                cur.execute(f"create role {rt_role} login nosuperuser nobypassrls "
                            f"nocreatedb nocreaterole password '{rt_pw}'")
        mig_dsn = (f"host={host_cn} {_addr} port={port} dbname=mrprofile user={mig_role} "
                   f"password={superpw} sslmode=verify-full sslrootcert={ca_path}")
        if apply_migrations:
            import backend.app.migrations as M
            M.apply_migrations(mig_dsn, migrations_dir=M.BASELINE_DIR)
            # grant the restricted runtime the app group so RLS applies to it
            with psycopg.connect(mig_dsn, autocommit=True) as c:
                with c.cursor() as cur:
                    cur.execute(f"grant monday_report_app to {rt_role}")
        runtime_dsn = (f"host={host_cn} {_addr} port={port} dbname=mrprofile user={rt_role} "
                       f"password={rt_pw} sslmode=verify-full sslrootcert={ca_path}")
        plaintext_dsn = (f"host={host_cn} {_addr} port={port} dbname=mrprofile user={rt_role} "
                         f"password={rt_pw} sslmode=disable")
        yield {
            "container": name,
            "runtime_dsn": runtime_dsn,
            "migration_dsn": mig_dsn,
            "admin_dsn": admin_dsn,
            "plaintext_dsn": plaintext_dsn,
            "ca_path": ca_path,
            "runtime_role": rt_role,
            "migration_role": mig_role,
            "host": host_cn,
            "port": port,
        }
    finally:
        if created:
            _run(["docker", "rm", "-f", name], check=False, timeout=60)
            _run(["docker", "volume", "rm", "-f", volume], check=False, timeout=60)
        with contextlib.suppress(Exception):
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
