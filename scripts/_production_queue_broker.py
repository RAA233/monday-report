"""Disposable TLS-enabled Redis broker provisioning for the production-queue behavioral
tier. Everything is EPHEMERAL: a runner-owned Docker Redis, a disposable self-signed CA +
server cert, disposable password, disposable stream/group/DLQ. Connects to nothing real.

Provides ``disposable_redis(tls=True)`` yielding a dict describing the live broker
(rediss:// or redis:// URL, CA path, stream/group/dlq keys) and tearing it down on exit.
"""
from __future__ import annotations

import contextlib
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

IMAGE = "redis:7-alpine"


def _run(args, *, timeout=90, check=True):
    proc = subprocess.run(args, capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"cmd failed ({proc.returncode}): {' '.join(args[:2])} :: "
                           f"{proc.stderr.decode('utf-8','replace')[:200]}")
    return proc


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _certs(certdir: Path, cn: str) -> None:
    ca_key, ca_crt = certdir / "ca.key", certdir / "ca.crt"
    srv_key, srv_csr, srv_crt = certdir / "server.key", certdir / "server.csr", certdir / "server.crt"
    ext = certdir / "san.ext"
    ext.write_text(f"subjectAltName=DNS:{cn}\nextendedKeyUsage=serverAuth\n")
    _run(["openssl", "genrsa", "-out", str(ca_key), "2048"])
    _run(["openssl", "req", "-x509", "-new", "-nodes", "-key", str(ca_key), "-sha256",
          "-days", "2", "-subj", "/CN=disposable-queue-ca", "-out", str(ca_crt)])
    _run(["openssl", "genrsa", "-out", str(srv_key), "2048"])
    _run(["openssl", "req", "-new", "-key", str(srv_key), "-subj", f"/CN={cn}", "-out", str(srv_csr)])
    _run(["openssl", "x509", "-req", "-in", str(srv_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
          "-CAcreateserial", "-days", "2", "-sha256", "-extfile", str(ext), "-out", str(srv_crt)])


@contextlib.contextmanager
def disposable_redis(*, tls: bool = True) -> Iterator[dict]:
    run_hash = secrets.token_hex(6)
    name = f"mr-q-{run_hash}"
    port = _free_port()
    pw = secrets.token_hex(16)
    cn = "localhost"
    tmp = Path(tempfile.mkdtemp(prefix=f"mrqueue_{run_hash}_"))
    certdir = tmp / "certs"; certdir.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        if tls:
            _certs(certdir, cn)
            # start with the certs mounted; TLS-only (no plaintext port)
            _run(["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:6379",
                  "-v", f"{certdir}:/certs:ro", IMAGE, "redis-server",
                  "--port", "0", "--tls-port", "6379",
                  "--tls-cert-file", "/certs/server.crt", "--tls-key-file", "/certs/server.key",
                  "--tls-ca-cert-file", "/certs/ca.crt", "--tls-auth-clients", "no",
                  "--requirepass", pw, "--appendonly", "yes", "--maxmemory-policy", "noeviction"],
                 timeout=120)
        else:
            _run(["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:6379", IMAGE,
                  "redis-server", "--requirepass", pw, "--appendonly", "yes",
                  "--maxmemory-policy", "noeviction"], timeout=120)
        created = True
        ca_path = (certdir / "ca.crt").as_posix()
        if tls:
            # rediss:// with server-cert verification against the disposable CA
            url = (f"rediss://:{pw}@{cn}:{port}/0?ssl_cert_reqs=required&ssl_ca_certs={ca_path}")
            plaintext_url = f"redis://:{pw}@{cn}:{port}/0"
        else:
            url = f"redis://:{pw}@{cn}:{port}/0"
            plaintext_url = url
        # readiness
        import redis
        deadline = time.monotonic() + 40
        while True:
            try:
                redis.Redis.from_url(url, socket_connect_timeout=3).ping()
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise RuntimeError("disposable redis did not become ready")
                time.sleep(0.4)
        yield {
            "container": name, "url": url, "plaintext_url": plaintext_url, "ca_path": ca_path,
            "host": cn, "port": port, "tls": tls,
            "stream_key": f"mrq:{run_hash}:jobs",
            "group": "workers",
            "dead_letter_key": f"mrq:{run_hash}:dead",
        }
    finally:
        if created:
            _run(["docker", "rm", "-f", name], check=False, timeout=60)
        with contextlib.suppress(Exception):
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
