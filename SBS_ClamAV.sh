
#!/bin/bash
# SBS ClamAV Web Interface Installer by Bas
# Version: 1.0.0 

# Configuration
APP_ROOT="/opt/clamav-web"
APP_USER="clamav-web"
APP_GROUP="clamav-web"
APP_SERVICE="clamav-web"
APP_PORT=5000
LOG_FILE="/tmp/clamav-web-install.log"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() { 
    echo -e "${GREEN}[INSTALL]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

# Check if running as root
require_root() {
    if [[ $(id -u) -ne 0 ]]; then
        error "This installer must be run as root (use sudo)"
        exit 1
    fi
}

# Detect package manager
detect_pkg_mgr() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# Install required packages
install_packages() {
    local pkg_mgr=$(detect_pkg_mgr)
    log "Installing system packages using $pkg_mgr..."
    
    case "$pkg_mgr" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || error "Failed to update package list"
            apt-get install -y \
                clamav clamav-freshclam \
                python3 python3-venv python3-pip \
                sqlite3 curl coreutils findutils procps jq \
                || error "Failed to install packages"
            ;;
        dnf)
            dnf install -y epel-release || true
            dnf install -y \
                clamav clamav-update \
                python3 python3-pip \
                sqlite curl coreutils findutils procps-ng jq \
                || error "Failed to install packages"
            ;;
        yum)
            yum install -y epel-release || true
            yum install -y \
                clamav clamav-update \
                python3 python3-pip \
                sqlite curl coreutils findutils procps-ng jq \
                || error "Failed to install packages"
            ;;
        pacman)
            pacman -Sy --noconfirm \
                clamav python python-pip \
                sqlite curl coreutils findutils procps-ng jq \
                || error "Failed to install packages"
            ;;
        *)
            error "Unsupported package manager. Please manually install:"
            error "clamav, python3-venv, python3-pip, sqlite3, curl, jq"
            exit 1
            ;;
    esac
}

# Create application user
create_user() {
    log "Creating application user: $APP_USER"
    
    if id "$APP_USER" &>/dev/null; then
        warning "User $APP_USER already exists"
    else
        useradd -r -s /bin/bash -d "$APP_ROOT" -m "$APP_USER" || {
            error "Failed to create user"
            exit 1
        }
        log "Created user: $APP_USER"
    fi
}

# Create directory structure
create_dirs() {
    log "Creating directory structure..."
    
    mkdir -p "$APP_ROOT"/{templates,static,quarantine,logs,tools,data} || {
        error "Failed to create directories"
        exit 1
    }
    
    # Set secure permissions
    chmod 700 "$APP_ROOT/quarantine"
    chmod 755 "$APP_ROOT"/{templates,static,logs,tools,data}
    
    # Create initial log file
    touch "$APP_ROOT/logs/app.log"
    
    # Set ownership
    chown -R "$APP_USER:$APP_GROUP" "$APP_ROOT"
    
    log "Directory structure created"
}

# Create Python virtual environment
create_venv() {
    log "Creating Python virtual environment..."
    
    if [[ -d "$APP_ROOT/venv" ]]; then
        warning "Virtual environment already exists, recreating..."
        rm -rf "$APP_ROOT/venv"
    fi
    
    # Create venv as the app user
    sudo -u "$APP_USER" python3 -m venv "$APP_ROOT/venv" || {
        error "Failed to create virtual environment"
        exit 1
    }
    
    # Install required packages
    log "Installing Python packages..."
    sudo -u "$APP_USER" "$APP_ROOT/venv/bin/pip" install --upgrade pip || {
        error "Failed to upgrade pip"
        exit 1
    }
    
    sudo -u "$APP_USER" "$APP_ROOT/venv/bin/pip" install Flask==2.3.3 || {
        error "Failed to install Flask"
        exit 1
    }
    
    log "Python environment ready"
}

# Write application files
write_app_files() {
    log "Writing application files..."
    
    # Write VERSION file
    cat > "$APP_ROOT/VERSION.txt" << 'VERSION_EOF'
ClamAV-Web v2.0.0 - Fixed Production Build
VERSION_EOF

    # Write the main application (app.py)
    cat > "$APP_ROOT/app.py" << 'APP_EOF'
#!/usr/bin/env python3
"""
SBS ClamAV Web Interface 
"""
import os
import sys
import json
import time
import shlex
import queue
import signal
import sqlite3
import shutil
import threading
import tempfile
import subprocess
from collections import deque
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

from flask import Flask, jsonify, request, Response, render_template, send_from_directory
from werkzeug.utils import secure_filename

# ======== Configuration ========
HOST = os.environ.get("CLAMAV_WEB_HOST", "0.0.0.0")
PORT = int(os.environ.get("CLAMAV_WEB_PORT", "5000"))
APP_ROOT = Path("/opt/clamav-web")
LOG_DIR = APP_ROOT / "logs"
LOG_FILE = LOG_DIR / "app.log"
DATA_DIR = APP_ROOT / "data"
QUARANTINE_DIR = APP_ROOT / "quarantine"
DB_PATH = DATA_DIR / "scanlog.db"
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
DEFAULT_SCAN_ARGS = ["-i", "--max-filesize=100M", "--max-scansize=100M"]

# Ensure directories exist
for dir_path in [LOG_DIR, DATA_DIR, QUARANTINE_DIR]:
    os.makedirs(dir_path, exist_ok=True)

# ======== Logging ========
import logging
from logging.handlers import RotatingFileHandler

logger = logging.getLogger("clamav_web")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

# File handler
fh = RotatingFileHandler(str(LOG_FILE), maxBytes=10*1024*1024, backupCount=5)
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(fh)

# Console handler
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.INFO)
sh.setFormatter(formatter)
logger.addHandler(sh)

logger.info("[BOOT] Starting ClamAV Web Interface v1.0.0")

# ======== Flask App ========
app = Flask(__name__, 
            template_folder=str(APP_ROOT / "templates"), 
            static_folder=str(APP_ROOT / "static"))
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# ======== Database ========
_db_lock = threading.Lock()

def get_db() -> sqlite3.Connection:
    """Get database connection with proper settings"""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initialize database schema"""
    with _db_lock:
        conn = get_db()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    path TEXT NOT NULL,
                    files_scanned INTEGER DEFAULT 0,
                    infected_count INTEGER DEFAULT 0,
                    duration_seconds INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON scan_history(timestamp)
            """)
            conn.commit()
            logger.info("[DB] Database initialized successfully")
        except Exception as e:
            logger.error(f"[DB] Failed to initialize: {e}")
            raise
        finally:
            conn.close()

# Initialize database on startup
init_db()

# ======== Global State ========
state_lock = threading.Lock()
output_buffer = deque(maxlen=2000)
last_cursor = 0
scan_proc = None
scan_db_id = None
scan_start_ts = None
is_scanning = False
is_updating = False
summary_counts = {"files_scanned": 0, "infected_count": 0}

# ======== Helper Functions ========
def append_output(line: str) -> None:
    """Add line to output buffer"""
    global last_cursor
    with state_lock:
        line = line.rstrip('\n')
        output_buffer.append(line)
        last_cursor += 1

def which(binary: str) -> bool:
    """Check if binary exists in PATH"""
    return shutil.which(binary) is not None

def get_db_version() -> str:
    """Get ClamAV database version"""
    if not which("clamscan"):
        return "ClamAV not installed"
    try:
        result = subprocess.run(
            ["clamscan", "--version"], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.splitlines()[0].strip()
    except Exception as e:
        logger.error(f"[STATUS] Failed to get version: {e}")
    return "Unknown"

def get_freshclam_last_update() -> str:
    """Get last freshclam update time"""
    log_paths = [
        "/var/log/clamav/freshclam.log",
        "/var/log/freshclam.log",
        "/var/log/clamav/freshclam.log.1"
    ]
    
    for path in log_paths:
        try:
            if os.path.exists(path):
                stat = os.stat(path)
                return datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
        except Exception:
            continue
    return "Unknown"

def sanitize_path(path_str: str) -> Path:
    """Sanitize and resolve path"""
    try:
        path = Path(path_str).expanduser().resolve()
        # Ensure it's an absolute path
        if not path.is_absolute():
            path = Path("/") / path
        return path
    except Exception:
        return Path("/")

# ======== Routes ========
@app.route("/")
def index():
    """Serve main interface"""
    return render_template("index.html")

@app.route("/api/status")
def api_status():
    """Get system status"""
    global is_scanning, is_updating
    
    status = {
        "clamav": which("clamscan"),
        "freshclam": which("freshclam"),
        "db_version": get_db_version(),
        "last_update": get_freshclam_last_update(),
        "is_scanning": bool(is_scanning),
        "is_updating": bool(is_updating)
    }
    
    logger.info(f"[STATUS] {status}")
    return jsonify(status)

@app.route("/api/browse/")
@app.route("/api/browse/<path:folder>")
def api_browse(folder: Optional[str] = None):
    """Browse filesystem"""
    if folder is None:
        start_path = Path("/")
    else:
        start_path = sanitize_path("/" + folder.lstrip("/"))
    
    result = {
        "current": str(start_path),
        "parent": str(start_path.parent) if start_path != start_path.parent else None,
        "items": []
    }
    
    try:
        if start_path.is_dir():
            items = []
            for entry in sorted(start_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                if entry.name.startswith("."):
                    continue
                    
                try:
                    item = {
                        "name": entry.name,
                        "path": str(entry),
                        "is_dir": entry.is_dir()
                    }
                    if entry.is_file():
                        item["size"] = entry.stat().st_size
                    items.append(item)
                except PermissionError:
                    continue
                    
            result["items"] = items
            logger.info(f"[BROWSER] Listed {start_path}")
        return jsonify(result)
        
    except PermissionError:
        logger.warning(f"[BROWSER] Permission denied: {start_path}")
        return jsonify({"error": "Permission denied", **result}), 403
    except FileNotFoundError:
        logger.warning(f"[BROWSER] Not found: {start_path}")
        return jsonify({"error": "Not found", **result}), 404
    except Exception as e:
        logger.error(f"[BROWSER] Error: {e}")
        return jsonify({"error": str(e), **result}), 500

@app.route("/api/scan/custom", methods=["POST"])
def api_scan_custom():
    """Start custom scan"""
    global scan_proc, is_scanning, scan_db_id, scan_start_ts, summary_counts
    
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400
    
    if not data or "path" not in data:
        return jsonify({"error": "Missing 'path' parameter"}), 400
    
    target_path = sanitize_path(str(data.get("path")))
    recursive = bool(data.get("recursive", False))
    max_depth = data.get("max_depth")
    
    if not target_path.exists():
        return jsonify({"error": f"Path does not exist: {target_path}"}), 400
    
    with state_lock:
        if is_scanning:
            return jsonify({"error": "Scan already in progress"}), 409
        is_scanning = True
        summary_counts = {"files_scanned": 0, "infected_count": 0}
    
    # Insert database record
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scan_history(path, status) VALUES(?, 'running')",
            (str(target_path),)
        )
        conn.commit()
        scan_db_id = cursor.lastrowid
        logger.info(f"[DB] Created scan record id={scan_db_id} for {target_path}")
    except Exception as e:
        logger.error(f"[DB] Failed to create scan record: {e}")
        with state_lock:
            is_scanning = False
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()
    
    # Build scan command
    cmd = ["clamscan"] + DEFAULT_SCAN_ARGS + [
        "--exclude-dir", r"^/(proc|sys|dev|run|mnt|media|snap)($|/)"
    ]
    
    if recursive:
        cmd.append("-r")
        
    if isinstance(max_depth, int) and max_depth > 0:
        cmd += ["--max-dir-recursion", str(max_depth)]
        
    cmd.append(str(target_path))
    
    append_output("=== STARTING SCAN ===")
    append_output("$ " + " ".join(shlex.quote(x) for x in cmd))
    logger.info(f"[SCAN] Executing: {' '.join(shlex.quote(x) for x in cmd)}")
    
    def reader_thread(proc: subprocess.Popen):
        """Read scan output in background"""
        global is_scanning, scan_db_id, summary_counts
        
        files_scanned = 0
        infected_count = 0
        start_time = time.time()
        
        try:
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                    
                line = line.rstrip('\n')
                append_output(line)
                
                # Parse summary statistics
                if line.startswith("Scanned files:"):
                    try:
                        files_scanned = int(line.split(":", 1)[1].strip())
                        summary_counts["files_scanned"] = files_scanned
                    except Exception:
                        pass
                elif line.startswith("Infected files:"):
                    try:
                        infected_count = int(line.split(":", 1)[1].strip())
                        summary_counts["infected_count"] = infected_count
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.error(f"[SCAN] Reader thread error: {e}")
            append_output(f"Error reading scan output: {e}")
        finally:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                
            duration = int(time.time() - start_time)
            append_output("=== SCAN COMPLETE ===")
            
            with state_lock:
                is_scanning = False
            
            # Update database record
            if scan_db_id:
                conn = get_db()
                try:
                    conn.execute("""
                        UPDATE scan_history 
                        SET files_scanned=?, infected_count=?, 
                            duration_seconds=?, status='completed' 
                        WHERE id=?
                    """, (files_scanned, infected_count, duration, scan_db_id))
                    conn.commit()
                    logger.info(f"[DB] Updated scan {scan_db_id}: files={files_scanned}, infected={infected_count}, duration={duration}s")
                except Exception as e:
                    logger.error(f"[DB] Failed to update scan record: {e}")
                finally:
                    conn.close()
    
    # Start scan process
    scan_start_ts = time.time()
    try:
        scan_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid if os.name != 'nt' else None
        )
        
        # Start reader thread
        thread = threading.Thread(target=reader_thread, args=(scan_proc,), daemon=True)
        thread.start()
        
        return jsonify({"status": "started", "path": str(target_path)})
        
    except Exception as e:
        logger.error(f"[SCAN] Failed to start: {e}")
        with state_lock:
            is_scanning = False
        return jsonify({"error": str(e)}), 500

@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    """Stop running scan"""
    global scan_proc, scan_db_id
    
    with state_lock:
        proc = scan_proc
        
    if proc is None or proc.poll() is not None:
        append_output("--- NO ACTIVE SCAN ---")
        return jsonify({"status": "no_active_scan"})
    
    try:
        # Try graceful termination first
        try:
            if os.name != 'nt':
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.terminate()
        except Exception:
            proc.terminate()
        
        # Wait for process to exit
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Force kill if still running
            try:
                if os.name != 'nt':
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
            except Exception:
                proc.kill()
        
        append_output("--- SCAN STOPPED BY USER ---")
        logger.info("[SCAN] Stopped by user")
        
        # Update database
        if scan_db_id:
            conn = get_db()
            try:
                conn.execute(
                    "UPDATE scan_history SET status='stopped' WHERE id=?",
                    (scan_db_id,)
                )
                conn.commit()
            except Exception as e:
                logger.error(f"[DB] Failed to update stopped scan: {e}")
            finally:
                conn.close()
        
        return jsonify({"status": "stopped"})
        
    except Exception as e:
        logger.error(f"[SCAN] Stop error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/scan/output")
def api_scan_output():
    """Get scan output (polling endpoint)"""
    global last_cursor
    
    try:
        since = int(request.args.get('since', '0'))
    except (ValueError, TypeError):
        since = 0
    
    with state_lock:
        current_cursor = last_cursor
        max_len = len(output_buffer)
        
        # Determine which lines to return
        if since <= current_cursor - max_len:
            # Cursor too old, return last 100 lines
            lines = list(output_buffer)[-100:]
        elif since >= current_cursor:
            # No new lines
            lines = []
        else:
            # Return new lines since cursor
            new_count = current_cursor - since
            lines = list(output_buffer)[-min(new_count, 100):]
    
    return jsonify({
        "scanning": is_scanning,
        "lines": lines,
        "cursor": current_cursor
    })

@app.route("/api/scan/history")
def api_scan_history():
    """Get scan history"""
    conn = get_db()
    try:
        cursor = conn.execute("""
            SELECT id, timestamp, path, files_scanned, 
                   infected_count, duration_seconds, status 
            FROM scan_history 
            ORDER BY timestamp DESC 
            LIMIT 50
        """)
        rows = [dict(row) for row in cursor.fetchall()]
        return jsonify(rows)
    except Exception as e:
        logger.error(f"[HISTORY] Error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/api/upload-scan", methods=["POST"])
def api_upload_scan():
    """Upload and scan a file"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    safe_name = secure_filename(file.filename) or f"upload_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    temp_dir = tempfile.mkdtemp(prefix="clamup_")
    file_path = os.path.join(temp_dir, safe_name)
    
    try:
        # Save uploaded file
        file.save(file_path)
        size = os.path.getsize(file_path)
        
        # Scan file
        cmd = ["clamscan"] + DEFAULT_SCAN_ARGS + [file_path]
        logger.info(f"[UPLOAD] Scanning: {' '.join(shlex.quote(x) for x in cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            stdout = result.stdout or ""
        except subprocess.TimeoutExpired:
            stdout = "Scan timed out after 60 seconds"
        
        # Check if infected
        infected = False
        virus_name = None
        
        for line in stdout.splitlines():
            if line.strip().endswith("FOUND"):
                infected = True
                try:
                    # Extract virus name
                    parts = line.strip().rsplit(" ", 1)
                    if len(parts) > 0:
                        virus_part = parts[0].split(":", 1)
                        if len(virus_part) > 1:
                            virus_name = virus_part[1].strip()
                except Exception:
                    pass
                break
        
        # Quarantine if infected
        if infected:
            quarantine_path, meta_path = quarantine_file(
                file_path, 
                file.filename, 
                virus_name
            )
            logger.warning(f"[QUARANTINE] Infected file moved: {quarantine_path}")
        
        return jsonify({
            "filename": safe_name,
            "infected": infected,
            "virus_name": virus_name,
            "output": stdout,
            "size": size
        })
        
    except Exception as e:
        logger.error(f"[UPLOAD] Error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        # Cleanup temp directory
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

def quarantine_file(src_path: str, original_name: str, virus_name: Optional[str]) -> tuple:
    """Move infected file to quarantine"""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    
    # Generate unique quarantine filename
    base = os.path.basename(original_name) or "unknown"
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    dest_base = f"{base}.{timestamp}"
    dest_path = QUARANTINE_DIR / dest_base
    
    # Ensure unique filename
    counter = 0
    while dest_path.exists():
        counter += 1
        dest_path = QUARANTINE_DIR / f"{dest_base}.{counter}"
    
    # Move file to quarantine
    shutil.move(src_path, dest_path)
    
    # Get file permissions
    try:
        stat = dest_path.stat()
        perms = oct(stat.st_mode & 0o777)
    except Exception:
        perms = "0o600"
    
    # Create metadata
    meta = {
        "original_path": str(original_name),
        "quarantine_time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "size": dest_path.stat().st_size if dest_path.exists() else None,
        "permissions": perms,
        "virus_name": virus_name
    }
    
    # Save metadata
    meta_path = str(dest_path) + ".json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    
    # Secure quarantined file
    try:
        os.chmod(dest_path, 0o600)
    except Exception:
        pass
    
    return str(dest_path), meta_path

@app.route("/api/quarantine")
def api_quarantine_list():
    """List quarantined files"""
    items = []
    
    try:
        for entry in sorted(QUARANTINE_DIR.iterdir(), key=lambda p: p.name):
            if entry.name.endswith('.json'):
                continue
            
            # Build metadata path
            if entry.suffix:
                meta_path = entry.with_suffix(entry.suffix + ".json")
            else:
                meta_path = Path(str(entry) + ".json")
            
            # Basic file info
            info = {
                "filename": entry.name,
                "size": entry.stat().st_size if entry.exists() else None
            }
            
            # Load metadata if available
            try:
                if meta_path.exists():
                    with open(meta_path, "r", encoding="utf-8") as f:
                        metadata = json.load(f)
                        info.update(metadata)
            except Exception:
                pass
            
            items.append(info)
        
        return jsonify(items)
        
    except Exception as e:
        logger.error(f"[QUARANTINE] List error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/quarantine/<path:filename>", methods=["DELETE"])
def api_quarantine_delete(filename: str):
    """Delete quarantined file"""
    # Security check - no path traversal
    if "/" in filename or ".." in filename:
        return jsonify({"error": "Invalid filename"}), 400
    
    file_path = QUARANTINE_DIR / filename
    meta_path = Path(str(file_path) + ".json")
    
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    
    try:
        # Secure deletion if shred is available
        if shutil.which("shred"):
            subprocess.run(["shred", "-u", "-n", "1", str(file_path)], check=False)
            if meta_path.exists():
                subprocess.run(["shred", "-u", "-n", "1", str(meta_path)], check=False)
        else:
            # Regular deletion
            os.remove(file_path)
            if meta_path.exists():
                os.remove(meta_path)
        
        logger.info(f"[QUARANTINE] Deleted: {filename}")
        return jsonify({"status": "deleted"})
        
    except Exception as e:
        logger.error(f"[QUARANTINE] Delete error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/system/metrics")
def api_system_metrics():
    """Get system metrics"""
    metrics = {}
    
    def run_cmd(cmd: str, timeout: int = 5) -> str:
        try:
            result = subprocess.run(
                ["bash", "-c", cmd], 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return result.stdout.strip()
        except Exception:
            return "N/A"
    
    # Get metrics
    metrics["cpu"] = run_cmd("top -bn1 | grep 'Cpu(s)' | awk '{print 100-$8\"%\"}'") or "N/A"
    metrics["memory"] = run_cmd("free -m | awk '/Mem:/ {printf \"%.1f%%\", ($3/$2)*100}'") or "N/A"
    metrics["disk"] = run_cmd("df -h / | awk 'NR==2 {print $5}'") or "N/A"
    metrics["uptime"] = run_cmd("uptime -p") or run_cmd("uptime") or "N/A"
    
    logger.info(f"[METRICS] {metrics}")
    return jsonify(metrics)

# ======== Main ========
def run_app():
    """Run the Flask application"""
    app.run(host=HOST, port=PORT, threaded=True, debug=False)

if __name__ == "__main__":
    try:
        run_app()
    except Exception as e:
        logger.error(f"[BOOT] Application failed: {e}")
        raise
APP_EOF

    # Set proper permissions
    chmod 755 "$APP_ROOT/app.py"
    chown "$APP_USER:$APP_GROUP" "$APP_ROOT/app.py"
    
    log "Application file written"
}

# Write HTML template
write_templates() {
    log "Writing HTML templates..."
    
    cat > "$APP_ROOT/templates/index.html" << 'HTML_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SolidBeamSolution ClamAV Web Interface</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <header>
        <h1>🛡️ SBS ClamAV Web Interface</h1>
        <div id="status-bar">
            <span id="status-clamav">ClamAV: ?</span>
            <span id="status-freshclam">FreshClam: ?</span>
            <span id="status-db">DB: ?</span>
            <span id="status-last">Last Update: ?</span>
            <span id="status-states">State: idle</span>
        </div>
    </header>

    <nav class="tabs">
        <button class="tab-button active" data-tab="scanner">Scanner</button>
        <button class="tab-button" data-tab="upload">Upload & Scan</button>
        <button class="tab-button" data-tab="history">History</button>
        <button class="tab-button" data-tab="quarantine">Quarantine</button>
        <button class="tab-button" data-tab="system">System</button>
    </nav>

    <main>
        <section id="tab-scanner" class="tab active">
            <div class="panel">
                <h2>Quick Actions</h2>
                <button id="btn-quick-scan">Quick Scan (/home)</button>
                <button id="btn-full-scan">Full Scan (/)</button>
                <span class="hint">Caution: Full scan may take a long time</span>
            </div>

            <div class="panel">
                <h2>File Browser</h2>
                <div class="browser-controls">
                    <input type="text" id="browser-path" value="/">
                    <button id="btn-browse-up">Go Up</button>
                    <button id="btn-browse-refresh">Refresh</button>
                </div>
                <div class="scan-options">
                    <label><input type="checkbox" id="opt-recursive" checked> Recursive</label>
                    <label>Max Depth: <input type="number" id="opt-depth" min="1" value="10"></label>
                    <button id="btn-scan-selected">Scan Selected</button>
                </div>
                <div id="browser-list"></div>
            </div>

            <div class="panel">
                <h2>Scan Output</h2>
                <div class="terminal" id="terminal"></div>
                <div class="terminal-actions">
                    <button id="btn-clear">Clear</button>
                    <button id="btn-stop">Stop Scan</button>
                </div>
            </div>
        </section>

        <section id="tab-upload" class="tab">
            <div class="panel">
                <h2>Upload & Scan</h2>
                <input type="file" id="upload-file">
                <button id="btn-upload">Upload & Scan</button>
                <div class="upload-result" id="upload-result"></div>
            </div>
        </section>

        <section id="tab-history" class="tab">
            <div class="panel">
                <h2>Scan History (Last 50)</h2>
                <table id="history-table">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Path</th>
                            <th>Files</th>
                            <th>Infected</th>
                            <th>Duration (s)</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </section>

        <section id="tab-quarantine" class="tab">
            <div class="panel">
                <h2>Quarantine</h2>
                <div id="quarantine-list"></div>
            </div>
        </section>

        <section id="tab-system" class="tab">
            <div class="panel">
                <h2>System Metrics</h2>
                <div class="cards">
                    <div class="card">CPU: <span id="m-cpu">?</span></div>
                    <div class="card">Memory: <span id="m-mem">?</span></div>
                    <div class="card">Disk (/): <span id="m-disk">?</span></div>
                    <div class="card">Uptime: <span id="m-uptime">?</span></div>
                </div>
            </div>
        </section>
    </main>

    <script src="/static/app.js"></script>
</body>
</html>
HTML_EOF

    chown "$APP_USER:$APP_GROUP" "$APP_ROOT/templates/index.html"
    log "HTML template written"
}

# Write CSS
write_static_files() {
    log "Writing static files..."
    
    cat > "$APP_ROOT/static/style.css" << 'CSS_EOF'
:root {
    --bg: #0d1117;
    --fg: #c9d1d9;
    --muted: #8b949e;
    --accent: #58a6ff;
    --bad: #ff6b6b;
    --ok: #2ea043;
    --panel: #161b22;
    --border: #30363d;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background: var(--bg);
    color: var(--fg);
}

header {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
}

h1 {
    margin: 0;
    font-size: 20px;
}

#status-bar span {
    margin-right: 12px;
    color: var(--muted);
    font-size: 14px;
}

.tabs {
    display: flex;
    gap: 4px;
    padding: 8px;
    border-bottom: 1px solid var(--border);
}

.tab-button {
    background: #21262d;
    color: var(--fg);
    border: 1px solid var(--border);
    padding: 6px 12px;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.2s;
}

.tab-button:hover {
    background: #30363d;
}

.tab-button.active {
    background: var(--accent);
    color: white;
}

main {
    padding: 12px;
}

.tab {
    display: none;
}

.tab.active {
    display: block;
}

.panel {
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 16px;
    margin-bottom: 12px;
    border-radius: 8px;
}

.browser-controls,
.scan-options,
.terminal-actions {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-bottom: 8px;
}

#browser-list {
    max-height: 240px;
    overflow: auto;
    background: #0b0f14;
    border: 1px solid var(--border);
    padding: 8px;
    border-radius: 6px;
}

#browser-list ul {
    list-style: none;
    padding-left: 0;
    margin: 0;
}

#browser-list li {
    padding: 4px 6px;
    cursor: pointer;
}

#browser-list li:hover {
    background: #161b22;
}

.terminal {
    background: #000;
    color: #ccc;
    padding: 8px;
    height: 300px;
    overflow: auto;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 13px;
    border-radius: 6px;
}

.terminal .bad {
    color: var(--bad);
    font-weight: bold;
}

.terminal .info {
    color: var(--accent);
}

.hint {
    color: var(--muted);
    margin-left: 8px;
    font-size: 14px;
}

button {
    background: var(--accent);
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
    transition: opacity 0.2s;
}

button:hover {
    opacity: 0.9;
}

button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

input[type="text"],
input[type="number"] {
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--border);
    padding: 6px 8px;
    border-radius: 4px;
}

input[type="file"] {
    margin-bottom: 8px;
}

#history-table {
    width: 100%;
    border-collapse: collapse;
}

#history-table th,
#history-table td {
    border-bottom: 1px solid var(--border);
    padding: 8px;
    text-align: left;
}

#history-table td.bad {
    color: var(--bad);
    font-weight: 600;
}

.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 8px;
}

.card {
    background: #0f141b;
    border: 1px solid var(--border);
    padding: 12px;
    border-radius: 6px;
}

.q-row {
    display: grid;
    grid-template-columns: 1.5fr 2fr 1fr 1fr auto;
    gap: 8px;
    padding: 8px;
    border-bottom: 1px solid var(--border);
    align-items: center;
}

.upload-result {
    margin-top: 16px;
}

.upload-result pre {
    background: #000;
    color: #ccc;
    padding: 8px;
    border-radius: 4px;
    overflow: auto;
    max-height: 200px;
}
CSS_EOF

    # Write JavaScript
    cat > "$APP_ROOT/static/app.js" << 'JS_EOF'
// ClamAV Web Interface - Client JavaScript

// State
let lastCursor = 0;
let idleCycles = 0;

// Tab system
document.querySelectorAll('.tab-button').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        document.querySelector('#tab-' + btn.dataset.tab).classList.add('active');
    });
});

// Terminal
const terminal = document.getElementById('terminal');
const statusStates = document.getElementById('status-states');

function appendLine(text) {
    const line = document.createElement('div');
    line.textContent = text;
    
    if (text.includes('FOUND') || text.toLowerCase().includes('infected')) {
        line.classList.add('bad');
    }
    if (text.includes('UPDATING') || text.toLowerCase().includes('update')) {
        line.classList.add('info');
    }
    
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

// Output polling
async function pollOutput() {
    try {
        const res = await fetch(`/api/scan/output?since=${lastCursor}`);
        const data = await res.json();
        
        (data.lines || []).forEach(appendLine);
        
        if (typeof data.cursor === 'number') {
            lastCursor = data.cursor;
        }
        
        document.getElementById('btn-stop').disabled = !data.scanning;
        statusStates.textContent = `State: ${data.scanning ? 'scanning' : 'idle'}`;
        
        idleCycles = (data.lines && data.lines.length) ? 0 : idleCycles + 1;
    } catch (e) {
        console.error('Poll error:', e);
    }
    
    const delay = (idleCycles > 5) ? 3000 : 1000;
    setTimeout(pollOutput, delay);
}
pollOutput();

// Status updates
async function refreshStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        
        document.getElementById('status-clamav').textContent = 
            'ClamAV: ' + (data.clamav ? 'OK' : 'Missing');
        document.getElementById('status-freshclam').textContent = 
            'FreshClam: ' + (data.freshclam ? 'OK' : 'Missing');
        document.getElementById('status-db').textContent = 
            'DB: ' + data.db_version;
        document.getElementById('status-last').textContent = 
            'Last Update: ' + data.last_update;
    } catch (e) {
        console.error('Status error:', e);
    }
}
setInterval(refreshStatus, 5000);
refreshStatus();

// Quick scan actions
document.getElementById('btn-quick-scan').onclick = async () => {
    lastCursor = 0;
    terminal.innerHTML = '';
    await fetch('/api/scan/custom', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({path: '/home', recursive: true, max_depth: 10})
    });
};

document.getElementById('btn-full-scan').onclick = async () => {
    if (!confirm('Run full scan of /? This may take a long time.')) return;
    lastCursor = 0;
    terminal.innerHTML = '';
    await fetch('/api/scan/custom', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({path: '/', recursive: true, max_depth: 10})
    });
};

// Terminal actions
document.getElementById('btn-clear').onclick = () => {
    terminal.innerHTML = '';
};

document.getElementById('btn-stop').onclick = async () => {
    await fetch('/api/scan/stop', {method: 'POST'});
    lastCursor = 0;
};

// File browser
const browserList = document.getElementById('browser-list');
const browserPath = document.getElementById('browser-path');

async function loadBrowser(path) {
    const relative = path.startsWith('/') ? path.substring(1) : path;
    const url = '/api/browse/' + encodeURIComponent(relative);
    
    try {
        const res = await fetch(url);
        const data = await res.json();
        
        if (data.error) {
            browserList.textContent = 'Error: ' + data.error;
            return;
        }
        
        browserPath.value = data.current;
        
        const ul = document.createElement('ul');
        (data.items || []).forEach(item => {
            const li = document.createElement('li');
            li.textContent = (item.is_dir ? '[DIR] ' : '') + item.name + 
                           (item.size ? ` (${item.size} bytes)` : '');
            li.onclick = () => {
                if (item.is_dir) {
                    loadBrowser(item.path);
                } else {
                    document.getElementById('browser-path').value = item.path;
                }
            };
            ul.appendChild(li);
        });
        
        browserList.innerHTML = '';
        browserList.appendChild(ul);
    } catch (e) {
        console.error('Browser error:', e);
        browserList.textContent = 'Error loading directory';
    }
}
loadBrowser('/');

document.getElementById('btn-browse-refresh').onclick = () => {
    loadBrowser(browserPath.value || '/');
};

document.getElementById('btn-browse-up').onclick = () => {
    const path = browserPath.value || '/';
    const parent = path === '/' ? '/' : path.split('/').slice(0, -1).join('/') || '/';
    loadBrowser(parent);
};

document.getElementById('btn-scan-selected').onclick = async () => {
    const path = browserPath.value || '/';
    const recursive = document.getElementById('opt-recursive').checked;
    const depth = parseInt(document.getElementById('opt-depth').value || '10');
    
    lastCursor = 0;
    terminal.innerHTML = '';
    
    await fetch('/api/scan/custom', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({path, recursive, max_depth: depth})
    });
};

// Upload handling
document.getElementById('btn-upload').onclick = async () => {
    const fileInput = document.getElementById('upload-file');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Please select a file first');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    const resultDiv = document.getElementById('upload-result');
    resultDiv.innerHTML = 'Scanning...';
    
    try {
        const res = await fetch('/api/upload-scan', {
            method: 'POST',
            body: formData
        });
        
        const data = await res.json();
        
        resultDiv.innerHTML = '';
        
        const status = document.createElement('div');
        status.innerHTML = `
            <strong>File:</strong> ${data.filename} (${data.size || '?'} bytes)<br>
            <strong>Status:</strong> ${data.infected ? 
                '<span style="color: red">INFECTED</span>' : 
                '<span style="color: green">CLEAN</span>'}
            ${data.virus_name ? '<br><strong>Virus:</strong> ' + data.virus_name : ''}
        `;
        resultDiv.appendChild(status);
        
        if (data.output) {
            const pre = document.createElement('pre');
            pre.textContent = data.output;
            resultDiv.appendChild(pre);
        }
    } catch (e) {
        console.error('Upload error:', e);
        resultDiv.innerHTML = '<span style="color: red">Upload failed</span>';
    }
};

// History
async function refreshHistory() {
    try {
        const res = await fetch('/api/scan/history');
        const data = await res.json();
        
        const tbody = document.querySelector('#history-table tbody');
        tbody.innerHTML = '';
        
        data.forEach(row => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${row.timestamp}</td>
                <td>${row.path}</td>
                <td>${row.files_scanned}</td>
                <td class="${row.infected_count > 0 ? 'bad' : ''}">${row.infected_count}</td>
                <td>${row.duration_seconds || ''}</td>
                <td>${row.status}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('History error:', e);
    }
}
setInterval(refreshHistory, 10000);
refreshHistory();

// Quarantine
async function refreshQuarantine() {
    try {
        const res = await fetch('/api/quarantine');
        const data = await res.json();
        
        const qlist = document.getElementById('quarantine-list');
        qlist.innerHTML = '';
        
        if (data.length === 0) {
            qlist.innerHTML = '<p>No quarantined files</p>';
            return;
        }
        
        data.forEach(item => {
            const row = document.createElement('div');
            row.classList.add('q-row');
            row.innerHTML = `
                <span>${item.filename}</span>
                <span>${item.original_path || ''}</span>
                <span>${item.quarantine_time || ''}</span>
                <span>${item.size || ''} bytes</span>
            `;
            
            const deleteBtn = document.createElement('button');
            deleteBtn.textContent = 'Delete';
            deleteBtn.onclick = async () => {
                if (!confirm('Permanently delete this quarantined file?')) return;
                await fetch('/api/quarantine/' + encodeURIComponent(item.filename), {
                    method: 'DELETE'
                });
                refreshQuarantine();
            };
            row.appendChild(deleteBtn);
            
            qlist.appendChild(row);
        });
    } catch (e) {
        console.error('Quarantine error:', e);
    }
}
setInterval(refreshQuarantine, 15000);
refreshQuarantine();

// System metrics
async function refreshMetrics() {
    try {
        const res = await fetch('/api/system/metrics');
        const data = await res.json();
        
        document.getElementById('m-cpu').textContent = data.cpu;
        document.getElementById('m-mem').textContent = data.memory;
        document.getElementById('m-disk').textContent = data.disk;
        document.getElementById('m-uptime').textContent = data.uptime;
    } catch (e) {
        console.error('Metrics error:', e);
    }
}
setInterval(refreshMetrics, 10000);
refreshMetrics();
JS_EOF

    chown -R "$APP_USER:$APP_GROUP" "$APP_ROOT/static"
    log "Static files written"
}

# Initialize database
init_db_file() {
    log "Initializing database..."
    
    # Create data directory if not exists
    mkdir -p "$APP_ROOT/data"
    
    # Initialize database
    sudo -u "$APP_USER" sqlite3 "$APP_ROOT/data/scanlog.db" << 'SQL_EOF'
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    path TEXT NOT NULL,
    files_scanned INTEGER DEFAULT 0,
    infected_count INTEGER DEFAULT 0,
    duration_seconds INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running'
);
CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_history(timestamp);
SQL_EOF

    chown "$APP_USER:$APP_GROUP" "$APP_ROOT/data/scanlog.db"
    log "Database initialized"
}

# Write systemd service
write_systemd() {
    log "Writing systemd service..."
    
    cat > "/etc/systemd/system/${APP_SERVICE}.service" << SERVICE_EOF
[Unit]
Description=ClamAV Web Interface
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_ROOT}
ExecStart=${APP_ROOT}/venv/bin/python ${APP_ROOT}/app.py
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
KillMode=mixed
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    log "Systemd service created"
}

# Write cron jobs
write_cron() {
    log "Setting up cron jobs..."
    
    cat > "/etc/cron.d/clamav-web" << 'CRON_EOF'
# ClamAV Web Interface Maintenance
# Weekly full scan on Sunday at 2:30 AM
30 2 * * 0 root /usr/bin/clamscan -r -i --exclude-dir="^/(proc|sys|dev|run|mnt|media)($|/)" / 2>&1 | logger -t clamav-scan

# Daily freshclam update at 3:05 AM
5 3 * * * root /usr/bin/freshclam --quiet 2>&1 | logger -t freshclam
CRON_EOF

    log "Cron jobs configured"
}

# Update virus definitions
run_freshclam_once() {
    log "Updating virus definitions..."
    
    # Stop freshclam service temporarily
    systemctl stop clamav-freshclam 2>/dev/null || true
    
    # Run freshclam
    if freshclam; then
        log "Virus definitions updated successfully"
    else
        warning "Failed to update virus definitions - will retry later"
    fi
    
    # Restart freshclam service
    systemctl start clamav-freshclam 2>/dev/null || true
}

# Enable and start service
enable_start_service() {
    log "Enabling and starting service..."
    
    systemctl daemon-reload
    systemctl enable ${APP_SERVICE} || {
        error "Failed to enable service"
        exit 1
    }
    
    systemctl start ${APP_SERVICE} || {
        error "Failed to start service"
        exit 1
    }
    
    # Wait for service to be ready
    sleep 3
    
    if systemctl is-active --quiet ${APP_SERVICE}; then
        log "Service started successfully"
    else
        error "Service failed to start - check: journalctl -u ${APP_SERVICE}"
        exit 1
    fi
}

# Print final instructions
print_runbook() {
    local host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    
    echo
    info "============================================"
    info "SBS ClamAV Web Interface Installation Complete!"
    info "============================================"
    echo
    info "Service: ${APP_SERVICE} (port ${APP_PORT})"
    info "User: ${APP_USER}"
    info "Installation: ${APP_ROOT}"
    echo
    info "Access URL: http://${host_ip:-localhost}:${APP_PORT}/"
    echo
    info "Service Commands:"
    echo "  Start:   systemctl start ${APP_SERVICE}"
    echo "  Stop:    systemctl stop ${APP_SERVICE}"
    echo "  Status:  systemctl status ${APP_SERVICE}"
    echo "  Logs:    journalctl -u ${APP_SERVICE} -f"
    echo
    info "Application Logs:"
    echo "  tail -f ${APP_ROOT}/logs/app.log"
    echo
    info "Quick Tests:"
    echo "  curl http://localhost:${APP_PORT}/api/status | jq"
    echo "  curl http://localhost:${APP_PORT}/api/scan/history | jq"
    echo
    warning "IMPORTANT: This interface has NO AUTHENTICATION!"
    warning "Only use on trusted, isolated networks!"
    echo
    info "Installation log: ${LOG_FILE}"
    info "============================================"
}

# Main installation flow
main() {
    echo
    info "Starting SBS ClamAV Web Interface Installation"
    info "Version: 2.0.0 - Production Ready"
    echo
    
    require_root
    install_packages
    create_user
    create_dirs
    create_venv
    write_app_files
    write_templates
    write_static_files
    init_db_file
    write_systemd
    write_cron
    run_freshclam_once
    enable_start_service
    print_runbook
    
    echo
    log "Installation completed successfully!"
}

# Run main installation
main "$@"
