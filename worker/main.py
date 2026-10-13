"""Authorization-scoped, sequential Nmap assessment service.

Admin-approved NSE scripts are permitted for authorized scope. Higher-risk
scripts require an additionally isolated, exact-IP private lab opt-in.
"""
import csv
import io
import hmac
import ipaddress
import json
import os
import pathlib
import re
import shlex
import signal
import socket
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from defusedxml import ElementTree as ET
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

app = FastAPI(title="Nmap Command Center Scanner")
ROOT = pathlib.Path(os.getenv("DATA_DIR", "/data"))
ROOT.mkdir(parents=True, exist_ok=True)
QUARANTINE = ROOT / "custom-quarantine"
QUARANTINE.mkdir(parents=True, exist_ok=True)
SCOPES = [ipaddress.ip_network(x.strip()) for x in os.getenv(
    "ALLOWED_CIDRS", "127.0.0.0/8,::1/128"
).split(",") if x.strip()]
ALLOWED_HOSTNAMES = {x.strip().lower().rstrip(".") for x in os.getenv("ALLOWED_HOSTNAMES", "").split(",") if x.strip()}
MAX_TARGETS = min(1024, max(1, int(os.getenv("MAX_TARGETS", "256"))))
MAX_DURATION = min(3600, max(30, int(os.getenv("MAX_DURATION", "1800"))))
MAX_RATE = 150
MAX_SESSIONS = 2
LOCK = threading.RLock()
ACTIVE = set()
PROCS = {}
# Broad discovery and target-expansion scripts are never selectable: they can
# send traffic beyond the exact pinned scan targets. Version scripts are managed
# by Nmap -sV and cannot be selected as standalone scripts.
NEVER_EXECUTE_CATEGORIES = {"broadcast", "external", "malware"}
LAB_CATEGORIES = {"brute", "dos", "exploit", "fuzzer"}
REVIEW_CATEGORIES = {"intrusive"}
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
LAB_MODE_ENABLED = os.getenv("LAB_MODE_ENABLED", "false").strip().lower() == "true"
# Lab targets must be exact loopback/RFC1918/ULA IPs explicitly authorized in .env.
# Explicit lab IPs expand the effective scan scope only when lab mode is enabled.
PRIVATE_LAB_NETWORKS = tuple(ipaddress.ip_network(x) for x in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"))

def parse_lab_ips(value):
    ips = set()
    for raw in value.split(","):
        if not raw.strip():
            continue
        try:
            ip = ipaddress.ip_address(raw.strip())
        except ValueError as exc:
            raise ValueError(f"LAB_ALLOWED_IPS requires exact valid IP addresses: {raw!r}") from exc
        if not any(ip in network for network in PRIVATE_LAB_NETWORKS):
            raise ValueError(f"LAB_ALLOWED_IPS allows only loopback and RFC1918/ULA addresses: {ip}")
        ips.add(str(ip))
    return ips

LAB_ALLOWED_IPS = parse_lab_ips(os.getenv("LAB_ALLOWED_IPS", ""))
def policy_path():
    return ROOT / "approvals.json"


def load_policy():
    try:
        data = json.loads(policy_path().read_text())
        return {"cidrs": data.get("cidrs", []), "hostnames": data.get("hostnames", []),
                "scripts": data.get("scripts", []), "audit": data.get("audit", [])}
    except (ValueError, OSError):
        return {"cidrs": [], "hostnames": [], "scripts": [], "audit": []}


def save_policy(policy):
    file = policy_path()
    tmp = file.with_suffix(".tmp")
    tmp.write_text(json.dumps(policy, indent=2))
    tmp.replace(file)


def ensure_admin(token):
    if not ADMIN_TOKEN or len(ADMIN_TOKEN) < 16:
        raise HTTPException(503, "Configure a unique ADMIN_TOKEN (16+ characters) in .env to enable administrative approvals")
    if not token or not hmac.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(403, "Invalid administrator token")


def effective_scope():
    policy = load_policy()
    networks = list(SCOPES)
    for item in policy["cidrs"]:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    if LAB_MODE_ENABLED:
        networks.extend(ipaddress.ip_network(ip + ("/128" if ":" in ip else "/32")) for ip in LAB_ALLOWED_IPS)
    return networks, ALLOWED_HOSTNAMES | set(policy["hostnames"])


def restricted_category(categories, name):
    return (bool(NEVER_EXECUTE_CATEGORIES.intersection(categories))
            or name.startswith(("targets-", "broadcast-")) or "version" in categories)


def needs_lab(categories):
    return bool(LAB_CATEGORIES.intersection(categories))


def require_lab_targets(pinned_targets):
    if not LAB_MODE_ENABLED or not LAB_ALLOWED_IPS:
        raise HTTPException(403, "Private lab mode is disabled. Configure LAB_MODE_ENABLED=true and LAB_ALLOWED_IPS in .env")
    if len(pinned_targets) != 1 or pinned_targets[0] not in LAB_ALLOWED_IPS:
        raise HTTPException(403, "This NSE script requires one exact private lab IP listed in LAB_ALLOWED_IPS")

PROFILES = {
    "quick": ["-sT", "-F"],
    "full_tcp": ["-sT", "-p", "1-65535"],
    "services": ["-sT", "-sV", "--version-light"],
    "discovery": ["-sn"],
    "udp_top": ["-sU", "--top-ports", "20"],
    "os": ["-O"],
    "web": ["-sT", "-sV", "-p", "80,443,8080,8443"],
    "tls": ["-sT", "-p", "443,8443"],
    "windows": ["-sT", "-p", "139,445,3389"],
}
PROFILE_SCRIPTS = {
    "web": ["http-title", "http-headers", "http-security-headers"],
    "tls": ["ssl-cert"],
    "windows": ["smb-os-discovery", "smb-protocols", "smb2-security-mode", "rdp-ntlm-info"],
}
FALLBACK_SAFE = {"http-title", "http-headers", "http-security-headers", "ssl-cert", "ssh-hostkey", "ssh2-enum-algos", "banner", "smb-protocols", "dns-nsid"}
ENTRY = re.compile(r'Entry\s*\{\s*filename\s*=\s*"([\w.-]+)\.nse"\s*,\s*categories\s*=\s*\{([^}]+)\}', re.I)
SCRIPT_DB_LOCATIONS = [os.getenv("NMAP_SCRIPT_DB", "/usr/share/nmap/scripts/script.db"), "/usr/local/share/nmap/scripts/script.db"]


def catalog():
    for location in SCRIPT_DB_LOCATIONS:
        file = pathlib.Path(location)
        if file.is_file():
            content = file.read_text(encoding="utf8", errors="replace")
            result = []
            approved_scripts = set(load_policy()["scripts"])
            for name, raw_categories in ENTRY.findall(content):
                categories = sorted(set(re.findall(r'"([a-z]+)"', raw_categories)))
                prohibited = restricted_category(categories, name)
                reviewed = name in approved_scripts
                lab = needs_lab(categories)
                normal = (bool(set(categories).intersection({"safe", "default"}))
                          and not REVIEW_CATEGORIES.intersection(categories) and not lab)
                runnable = not prohibited and ((normal or reviewed) if not lab
                                               else (reviewed and LAB_MODE_ENABLED and bool(LAB_ALLOWED_IPS)))
                if prohibited:
                    availability = "unselectable"
                elif lab and not LAB_MODE_ENABLED:
                    availability = "lab_disabled"
                elif lab and not reviewed:
                    availability = "lab_review_required"
                elif lab:
                    availability = "lab_approved"
                elif runnable:
                    availability = "admin_approved" if reviewed and not normal else "enabled"
                else:
                    availability = "review_required"
                result.append({"name": name, "categories": categories, "runnable": runnable,
                               "labOnly": lab, "availability": availability, "source": "nmap"})
            if result:
                return sorted(result, key=lambda x: x["name"])
    return [{"name": n, "categories": ["safe"], "runnable": True, "labOnly": False, "availability": "enabled", "source": "fallback"} for n in sorted(FALLBACK_SAFE)]


def installed_libraries():
    root = pathlib.Path(os.getenv("NMAP_NSELIB_DIR", "/usr/share/nmap/nselib"))
    if not root.is_dir():
        return []
    return sorted(p.stem for p in root.glob("*.lua") if p.is_file())


def eligible_scripts():
    return {x["name"] for x in catalog() if x["runnable"]}


class Step(BaseModel):
    profile: str = "services"
    ports: str = ""
    timing: int = Field(default=3, ge=0, le=4)
    scripts: list[str] = Field(default_factory=list, max_length=40)
    version: bool = False
    traceroute: bool = False
    reason: bool = True
    skip_discovery: bool = False
    flags: str = Field(default="", max_length=3000)  # safe editable Nmap options, never shell code


class Scan(BaseModel):
    target: str = Field(min_length=1, max_length=4000)
    steps: list[Step] = Field(min_length=1, max_length=3)
    authorization_confirmed: bool = False
    lab_mode: bool = False
    lab_confirmed: bool = False


class Preview(Scan):
    pass


class ScopeApproval(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    note: str = Field(min_length=10, max_length=500)


class NSEApproval(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    note: str = Field(min_length=10, max_length=500)
    lab_acknowledged: bool = False


class CustomUpload(BaseModel):
    filename: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=100000)


def path(scan_id):
    if not re.fullmatch(r"[0-9a-f]{32}", scan_id):
        raise HTTPException(400, "Invalid scan ID")
    return ROOT / scan_id


def read(scan_id):
    file = path(scan_id) / "meta.json"
    if not file.exists():
        raise HTTPException(404, "Scan not found")
    return json.loads(file.read_text())


def save(scan_id, data):
    file = path(scan_id) / "meta.json"
    tmp = file.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(file)


def split_targets(value):
    parts = [x for x in re.split(r"[,\s]+", value.strip()) if x]
    if not parts:
        raise HTTPException(400, "Provide an IP, hostname, or HTTP(S) URL")
    if len(parts) > MAX_TARGETS:
        raise HTTPException(400, "Too many targets")
    results = []
    budget = 0
    scopes, hostnames = effective_scope()
    for item in parts:
        hostname = item
        if "://" in item:
            try:
                parsed = urlsplit(item)
                if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError("Invalid URL")
                hostname = parsed.hostname
            except ValueError:
                raise HTTPException(400, f"Invalid HTTP(S) URL: {item}")
        if "/" in hostname:
            try:
                net = ipaddress.ip_network(hostname, strict=False)
            except ValueError:
                raise HTTPException(400, "Invalid IP/CIDR target")
            if not any(net.subnet_of(allowed) for allowed in scopes):
                raise HTTPException(403, f"Target outside authorized scope: {item}")
            budget += net.num_addresses
            results.append(str(net))
            continue
        try:
            ip = ipaddress.ip_address(hostname.strip("[]"))
            if not any(ip in allowed for allowed in scopes):
                raise HTTPException(403, f"Target outside authorized scope: {item}")
            results.append(str(ip))
        except ValueError:
            host = hostname.lower().rstrip(".")
            if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or ".." in host:
                raise HTTPException(400, f"Invalid hostname: {hostname}")
            try:
                addresses = sorted({ipaddress.ip_address(answer[4][0]) for answer in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}, key=str)
            except (OSError, ValueError):
                raise HTTPException(400, f"Hostname could not be resolved: {host}")
            if not addresses:
                raise HTTPException(400, f"Hostname has no addresses: {host}")
            if host not in hostnames and not all(any(ip in net for net in scopes) for ip in addresses):
                raise HTTPException(403, f"Hostname outside authorized scope: {host}")
            # Pin resolved addresses to prevent a second DNS lookup by Nmap.
            results += [str(ip) for ip in addresses]
        budget += 1
        if budget > MAX_TARGETS:
            raise HTTPException(400, f"Maximum {MAX_TARGETS} addresses per session")
    if budget > MAX_TARGETS or len(results) > MAX_TARGETS:
        raise HTTPException(400, f"Maximum {MAX_TARGETS} addresses per session")
    return list(dict.fromkeys(results))


def check_scripts(names, pinned_targets=None, lab_confirmed=False, enforce_acknowledgement=False):
    unique = list(dict.fromkeys(names))
    if len(unique) > 40:
        raise HTTPException(400, "Maximum 40 NSE scripts per step")
    entries = {entry["name"]: entry for entry in catalog()}
    for name in unique:
        item = entries.get(name)
        if not item or not item["runnable"]:
            raise HTTPException(400, f"Unavailable or unapproved NSE script: {name}")
    lab_selected = [name for name in unique if entries[name]["labOnly"]]
    if lab_selected:
        require_lab_targets(pinned_targets or [])
        if len(lab_selected) > 3:
            raise HTTPException(400, "Maximum 3 higher-risk NSE scripts per lab step")
        if enforce_acknowledgement and not lab_confirmed:
            raise HTTPException(403, "Confirm the private-lab risk acknowledgement before launching")
    return unique


def check_ports(value):
    if not re.fullmatch(r"(?:[TU]:)?\d+(?:-(?:\d+)?)?(?:,(?:[TU]:)?\d+(?:-(?:\d+)?)?)*", value):
        raise HTTPException(400, "Invalid port selection")
    for number in re.findall(r"\d+", value):
        if int(number) < 1 or int(number) > 65535:
            raise HTTPException(400, "Port must be between 1 and 65535")
    return value


def parse_flags(value):
    """Only narrow discovery/inspection flags; targets and output are fixed server-side."""
    try:
        tokens = shlex.split(value)
    except ValueError:
        raise HTTPException(400, "Malformed command options")
    if tokens and tokens[0] == "nmap":
        tokens.pop(0)
    allowed_boolean = {"-sT", "-sU", "-sV", "-O", "-sn", "-Pn", "-F", "--reason", "--traceroute", "--open", "--version-light"}
    result, manual_scripts = [], []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in allowed_boolean or re.fullmatch(r"-T[0-4]", token):
            result.append(token)
        elif token in ("-p", "--top-ports", "--script"):
            if i + 1 >= len(tokens):
                raise HTTPException(400, f"Missing value for {token}")
            arg = tokens[i + 1]
            if token == "-p":
                check_ports(arg)
                result += [token, arg]
            elif token == "--top-ports":
                if not arg.isdecimal() or not 1 <= int(arg) <= 100:
                    raise HTTPException(400, "Top ports must be between 1 and 100")
                result += [token, arg]
            else:
                manual_scripts += arg.split(",")
            i += 1
        else:
            raise HTTPException(400, f"Disallowed command token: {token}. Edit options only; target/output are managed by the scanner.")
        i += 1
    if "-sn" in result and ("-sV" in result or "-O" in result):
        raise HTTPException(400, "Discovery-only mode conflicts with version or OS detection")
    # Selection and target/authorization checks are done in build_args.
    return result, manual_scripts


def build_args(step, pinned_targets, output, lab_confirmed=False, enforce_acknowledgement=False):
    if step.profile not in PROFILES:
        raise HTTPException(400, "Unknown profile")
    if step.flags.strip():
        flags, extra_scripts = parse_flags(step.flags)
    else:
        flags = PROFILES[step.profile].copy()
        if step.ports:
            check_ports(step.ports)
            for option in ("-p", "--top-ports"):
                if option in flags:
                    idx = flags.index(option)
                    del flags[idx:idx + 2]
            flags += ["-p", step.ports]
        if step.version and "-sV" not in flags and step.profile != "discovery":
            flags.append("-sV")
        if step.traceroute and step.profile != "discovery":
            flags.append("--traceroute")
        if step.reason:
            flags.append("--reason")
        if step.skip_discovery:
            flags.append("-Pn")
        flags += [f"-T{step.timing}"]
        extra_scripts = PROFILE_SCRIPTS.get(step.profile, [])
    # Never let client change rate ceiling, outputs, target or use an arbitrary shell command.
    names = check_scripts([*extra_scripts, *step.scripts], pinned_targets,
                          lab_confirmed, enforce_acknowledgement)
    high_risk = any(entry["labOnly"] for entry in catalog() if entry["name"] in names)
    if names:
        flags += ["--script", ",".join(names)]
    if high_risk:
        # Script rates are independent of packet rate; timeout is a second guard.
        flags += ["--script-timeout", "120s"]
    return ["nmap", *flags, "--max-rate", str(MAX_RATE), "--max-retries", "2", "-oA", str(output), *pinned_targets]


def parse(scan_id, step_index=0):
    base = path(scan_id)
    xml_file = base / f"scan-{step_index + 1}.xml"
    if not xml_file.exists() and step_index == 0:
        xml_file = base / "scan.xml"  # legacy jobs
    if not xml_file.exists():
        return {"hosts": [], "summary": {"hosts": 0, "openPorts": 0}, "findings": []}
    try:
        tree = ET.parse(xml_file)
        hosts = []
        findings = []
        for host in tree.findall(".//host"):
            address = host.find("address")
            status = host.find("status")
            ports = []
            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")
                ports.append({"port": int(port.get("portid", "0")), "protocol": port.get("protocol", ""),
                              "state": state.get("state", "") if state is not None else "",
                              "service": service.get("name", "") if service is not None else "",
                              "product": service.get("product", "") if service is not None else "",
                              "version": service.get("version", "") if service is not None else ""})
            host_address = address.get("addr", "") if address is not None else ""
            for node in host.findall(".//script"):
                parent_port = None
                for port_node in host.findall("./ports/port"):
                    if node in port_node.findall("./script"):
                        parent_port = port_node.get("portid")
                        break
                findings.append({"host": host_address, "port": parent_port,
                                 "id": node.get("id", ""), "output": node.get("output", "")[:5000]})
            hosts.append({"address": host_address,
                          "status": status.get("state", "unknown") if status is not None else "unknown", "ports": ports})
        return {"hosts": hosts, "summary": {"hosts": len(hosts), "openPorts": sum(p["state"] == "open" for h in hosts for p in h["ports"])}, "findings": findings}
    except Exception:
        return {"hosts": [], "summary": {"hosts": 0, "openPorts": 0}, "findings": []}


def execute(scan_id):
    base = path(scan_id)
    with (base / "live.log").open("a", buffering=1) as log:
        try:
            for idx, step in enumerate(read(scan_id)["steps"]):
                with LOCK:
                    meta = read(scan_id)
                    if meta["status"] == "cancelled":
                        break
                    meta["status"] = "running"
                    meta["activeStep"] = idx
                    meta["steps"][idx]["status"] = "running"
                    save(scan_id, meta)
                log.write(f"\n=== STEP {idx + 1}/{len(meta['steps'])}: {step['profile']} ===\n")
                try:
                    proc = subprocess.Popen(step["command"], stdout=log, stderr=subprocess.STDOUT,
                                            start_new_session=True, text=True)
                    with LOCK:
                        PROCS[scan_id] = proc
                        meta = read(scan_id)
                        meta["pid"] = proc.pid
                        save(scan_id, meta)
                        if meta["status"] == "cancelled":
                            os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        rc = proc.wait(timeout=MAX_DURATION)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGTERM)
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            os.killpg(proc.pid, signal.SIGKILL)
                            proc.wait()
                        rc = -1
                        log.write("\nStep exceeded configured duration.\n")
                    with LOCK:
                        meta = read(scan_id)
                        if meta["status"] == "cancelled":
                            meta["steps"][idx]["status"] = "cancelled"
                        else:
                            meta["steps"][idx]["status"] = "completed" if rc == 0 else "failed"
                        meta["steps"][idx]["exitCode"] = rc
                        save(scan_id, meta)
                        PROCS.pop(scan_id, None)
                    if rc != 0 or meta["status"] == "cancelled":
                        break
                except Exception as exc:
                    log.write(f"Step error: {exc}\n")
                    with LOCK:
                        meta = read(scan_id)
                        meta["steps"][idx]["status"] = "failed"
                        meta["error"] = str(exc)
                        save(scan_id, meta)
                    break
            with LOCK:
                meta = read(scan_id)
                if meta["status"] != "cancelled":
                    meta["status"] = "completed" if all(s["status"] == "completed" for s in meta["steps"]) else "failed"
                meta["finished"] = datetime.now(timezone.utc).isoformat()
                save(scan_id, meta)
        except Exception as exc:
            log.write(f"Session error: {exc}\n")
            with LOCK:
                meta = read(scan_id)
                meta["status"] = "failed"
                meta["error"] = str(exc)
                save(scan_id, meta)
        finally:
            with LOCK:
                ACTIVE.discard(scan_id)
                PROCS.pop(scan_id, None)


@app.get("/health")
def health():
    try:
        info = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5).stdout.splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired):
        info = "Nmap not detected"
    return {"ok": True, "version": info}


@app.get("/profiles")
def profiles():
    entries = catalog()
    scopes, names = effective_scope()
    return {"profiles": list(PROFILES), "scripts": entries, "libraries": installed_libraries(),
            "scope": sorted({str(s) for s in scopes}), "allowedHostnames": sorted(names),
            "adminApprovalConfigured": bool(ADMIN_TOKEN and len(ADMIN_TOKEN) >= 16),
            "labModeEnabled": LAB_MODE_ENABLED, "labAllowedIPs": sorted(LAB_ALLOWED_IPS),
            "maxTargets": MAX_TARGETS, "maxDuration": MAX_DURATION, "maxSteps": 3, "maxSessions": MAX_SESSIONS}


@app.post("/authorizations")
def authorize_target(approval: ScopeApproval, x_admin_token: str | None = Header(default=None)):
    ensure_admin(x_admin_token)
    target = approval.target.strip().lower().rstrip(".")
    if "://" in target:
        try:
            url = urlsplit(target)
            if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
                raise ValueError()
            target = url.hostname.lower()
        except ValueError:
            raise HTTPException(400, "Only valid HTTP(S) URLs can be approved")
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > MAX_TARGETS:
            raise HTTPException(400, f"Maximum {MAX_TARGETS} IP addresses per approved CIDR")
        target = str(network)
        field = "cidrs"
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", target) or ".." in target:
            raise HTTPException(400, "Specify an exact valid hostname, IP address or bounded CIDR")
        field = "hostnames"
    with LOCK:
        policy = load_policy()
        if target in policy[field]:
            raise HTTPException(409, "Scope entry is already approved")
        policy[field].append(target)
        policy["audit"].append({"action": "approve_target", "target": target, "note": approval.note,
                                "time": datetime.now(timezone.utc).isoformat()})
        save_policy(policy)
    return {"status": "approved", "target": target}


@app.post("/nse-approvals")
def approve_nse(approval: NSEApproval, x_admin_token: str | None = Header(default=None)):
    ensure_admin(x_admin_token)
    entry = next((script for script in catalog() if script["name"] == approval.name), None)
    if entry is None:
        raise HTTPException(404, "Script is not in the installed Nmap catalog")
    if restricted_category(entry["categories"], entry["name"]):
        raise HTTPException(403, "This script can target other systems, or is managed internally by Nmap")
    if entry["labOnly"]:
        if not LAB_MODE_ENABLED or not LAB_ALLOWED_IPS:
            raise HTTPException(403, "Private lab mode and an exact LAB_ALLOWED_IPS target are required")
        if not approval.lab_acknowledged:
            raise HTTPException(403, "Administrator must explicitly acknowledge higher-risk private lab scripts")
    with LOCK:
        policy = load_policy()
        if entry["name"] not in policy["scripts"]:
            policy["scripts"].append(entry["name"])
            policy["audit"].append({"action": "approve_lab_nse" if entry["labOnly"] else "approve_nse",
                                    "script": entry["name"], "lab_acknowledged": approval.lab_acknowledged,
                                    "note": approval.note, "time": datetime.now(timezone.utc).isoformat()})
            save_policy(policy)
    return {"status": "approved", "name": entry["name"]}


@app.get("/approvals-audit")
def approvals_audit(x_admin_token: str | None = Header(default=None)):
    ensure_admin(x_admin_token)
    return {"items": load_policy()["audit"][-100:]}


@app.get("/custom-scripts")
def custom_scripts():
    return {"items": [{"filename": p.name, "bytes": p.stat().st_size, "status": "quarantined"}
                      for p in sorted(QUARANTINE.iterdir()) if p.is_file()]}


@app.post("/custom-scripts")
def custom_upload(upload: CustomUpload):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}\.(?:nse|lua)", upload.filename):
        raise HTTPException(400, "Upload .nse or .lua files with simple filenames")
    if "\x00" in upload.content:
        raise HTTPException(400, "Invalid script content")
    filename = QUARANTINE / upload.filename
    try:
        with filename.open("x", encoding="utf8") as stream:
            stream.write(upload.content)
    except FileExistsError:
        raise HTTPException(409, "A file with this name already exists")
    return {"filename": upload.filename, "status": "quarantined", "message": "Stored for administrative review; not executable."}


@app.post("/preview")
def preview(scan: Preview):
    resolved = split_targets(scan.target)
    commands = [build_args(step, resolved, f"<session>/scan-{idx + 1}", scan.lab_confirmed) for idx, step in enumerate(scan.steps)]
    return {"commands": commands, "resolvedTargets": resolved}


@app.get("/scans")
def list_scans():
    items = []
    for file in ROOT.glob("*/meta.json"):
        try:
            items.append(json.loads(file.read_text()))
        except (ValueError, OSError):
            pass
    return sorted(items, key=lambda s: s["created"], reverse=True)[:300]


@app.post("/scans")
def start(scan: Scan, x_admin_token: str | None = Header(default=None)):
    if not scan.authorization_confirmed:
        raise HTTPException(403, "Confirm target authorization before starting an assessment")
    resolved = split_targets(scan.target)
    # Additional protected approval for lab-classified scripts (brute/dos/exploit/fuzzer).
    selected = set()
    for step in scan.steps:
        selected.update(step.scripts)
        if step.flags:
            _flags, manual = parse_flags(step.flags)
            selected.update(manual)
        else:
            selected.update(PROFILE_SCRIPTS.get(step.profile, []))
    lab_only = {x["name"] for x in catalog() if x.get("labOnly")}
    if selected.intersection(lab_only):
        if not scan.lab_mode or not scan.lab_confirmed:
            raise HTTPException(403, "Confirm private lab mode and disruptive-script risk acknowledgement")
        require_lab_targets(resolved)
        ensure_admin(x_admin_token)
    scan_id = uuid.uuid4().hex
    base = path(scan_id)
    # Build and validate ALL steps before reserving a worker slot.
    steps = [{"profile": step.profile, "command": build_args(step, resolved, base / f"scan-{idx + 1}",
                                                        scan.lab_confirmed, True),
              "status": "queued", "exitCode": None} for idx, step in enumerate(scan.steps)]
    with LOCK:
        if len(ACTIVE) >= MAX_SESSIONS:
            raise HTTPException(429, "Maximum two sessions currently active")
        base.mkdir()
        meta = {"id": scan_id, "target": scan.target, "resolvedTargets": resolved,
                "authorizationConfirmed": True, "labMode": scan.lab_mode, "labConfirmed": scan.lab_confirmed,
                "profile": steps[0]["profile"], "status": "queued", "activeStep": None,
                "created": datetime.now(timezone.utc).isoformat(), "finished": None,
                "command": steps[0]["command"], "steps": steps}
        save(scan_id, meta)
        (base / "live.log").touch()
        ACTIVE.add(scan_id)
        threading.Thread(target=execute, args=(scan_id,), daemon=True).start()
    return meta


@app.get("/scans/{scan_id}")
def detail(scan_id: str):
    meta = read(scan_id)
    index = meta.get("activeStep") or 0
    return {**meta, "results": parse(scan_id, index),
            "stepResults": [parse(scan_id, idx) for idx in range(len(meta.get("steps", [])))]}


@app.get("/scans/{scan_id}/logs")
def logs(scan_id: str, offset: int = 0):
    read(scan_id)
    file = path(scan_id) / "live.log"
    data = file.read_bytes() if file.exists() else b""
    offset = max(0, min(offset, len(data)))
    return {"text": data[offset:offset + 100000].decode("utf8", "replace"),
            "offset": min(len(data), offset + 100000), "total": len(data)}


@app.post("/scans/{scan_id}/cancel")
def cancel(scan_id: str):
    with LOCK:
        meta = read(scan_id)
        if meta["status"] in ("queued", "running"):
            meta["status"] = "cancelled"
            meta["finished"] = datetime.now(timezone.utc).isoformat()
            save(scan_id, meta)
            proc = PROCS.get(scan_id)
            if proc and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
    return read(scan_id)


@app.get("/scans/{scan_id}/export/{format}")
def export(scan_id: str, format: str, step: int = 0):
    meta = read(scan_id)
    total = len(meta.get("steps", [1]))
    if not 0 <= step < total:
        raise HTTPException(400, "Invalid step number")
    base = path(scan_id)
    if format in ("xml", "nmap", "gnmap", "log"):
        file = (base / "live.log") if format == "log" else (base / f"scan-{step + 1}.{format}")
        if not file.exists() and step == 0 and format != "log":
            file = base / f"scan.{format}"
        if not file.exists():
            raise HTTPException(404, "Output not available yet")
        return FileResponse(file, filename=f"{scan_id}-step-{step + 1}.{format if format != 'log' else 'txt'}",
                            media_type="application/octet-stream")
    if format == "json":
        return Response(json.dumps({**meta, "results": parse(scan_id, step)}, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}-step-{step + 1}.json"'})
    if format == "csv":
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(["host", "status", "port", "protocol", "state", "service", "product", "version"])
        for host in parse(scan_id, step)["hosts"]:
            for port in host["ports"]:
                writer.writerow([host["address"], host["status"], *[port[k] for k in
                                ("port", "protocol", "state", "service", "product", "version")]])
        return Response(stream.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{scan_id}-step-{step + 1}.csv"'})
    raise HTTPException(400, "Unsupported format")
