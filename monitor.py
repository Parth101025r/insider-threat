"""
Windows Log Collector
---------------------
Records the following events to a rotating log file:

  1. NEW_FILE      - a new file is created in the watched folders
  2. POWER events  - boot, clean shutdown, unexpected shutdown, restart/shutdown request
  3. MAIL_SENT     - an email was sent via desktop Outlook (with its size in bytes)
     MAIL_NOT_SENT - an email has been stuck in the Outlook Outbox too long

Install:   pip install watchdog pywin32
Run:       python log_collector.py
Autostart: Task Scheduler -> "At log on" (or "At startup") -> python.exe log_collector.py

Only metadata is logged (no file contents, no email bodies).
"""

import ctypes
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import re
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ----------------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------------
HOME = Path.home()

# Folders to watch for new files (recursive). Add more as needed.
WATCH_DIRS = [HOME / "Desktop", HOME / "Documents", HOME / "Downloads"]

# Ignore temp/partial files created by apps (Office, browsers, etc.)
IGNORE_SUFFIXES = (".tmp", ".crdownload", ".part", ".partial", ".swp", ".lnk")
IGNORE_PREFIXES = ("~$", ".~", "~")
IGNORE_DIR_PARTS = ("appdata", "$recycle.bin", ".git", "node_modules", "__pycache__")

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "collector.log"
STATE_FILE = LOG_DIR / "state.json"

MAIL_POLL_SECONDS = 15
POWER_POLL_SECONDS = 60
OUTBOX_STUCK_SECONDS = 180      # mail sitting in Outbox longer than this = "not sent"
LOG_MAIL_SUBJECT = False        # set True if you also want subjects logged

# Windows System-log event IDs that describe power state
POWER_EVENT_IDS = {
    6005: "BOOT (event log service started)",
    6006: "CLEAN_SHUTDOWN (event log service stopped)",
    6008: "UNEXPECTED_SHUTDOWN (previous shutdown was not clean)",
    41:   "UNEXPECTED_REBOOT (Kernel-Power, system rebooted without clean shutdown)",
    1074: "SHUTDOWN_OR_RESTART_REQUESTED",
}

# ----------------------------------------------------------------------------
# LOGGING SETUP
# ----------------------------------------------------------------------------
LOG_DIR.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("collector")
logger.setLevel(logging.INFO)
_fmt = logging.Formatter("%(asctime)s | %(message)s", "%Y-%m-%d %H:%M:%S")
_fh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
_fh.setFormatter(_fmt)
_ch = logging.StreamHandler(sys.stdout)
_ch.setFormatter(_fmt)
logger.addHandler(_fh)
logger.addHandler(_ch)

stop_event = threading.Event()


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def save_state(state: dict) -> None:
    try:
        STATE_FILE.write_text(json.dumps(state))
    except Exception as e:
        logger.error("STATE_SAVE_FAILED | %s", e)


# ----------------------------------------------------------------------------
# 1) NEW FILE DETECTION
# ----------------------------------------------------------------------------
class NewFileHandler(FileSystemEventHandler):
    def _ignored(self, path: str) -> bool:
        p = Path(path)
        name = p.name.lower()
        if name.endswith(IGNORE_SUFFIXES) or name.startswith(IGNORE_PREFIXES):
            return True
        return any(part.lower() in IGNORE_DIR_PARTS for part in p.parts)

    def on_created(self, event):
        if event.is_directory or self._ignored(event.src_path):
            return
        try:
            size = os.path.getsize(event.src_path)
        except OSError:
            size = -1
        logger.info("NEW_FILE | path=%s | size_bytes=%s", event.src_path, size)

    def on_moved(self, event):
        # A file renamed/moved INTO a watched folder also appears as "new" there
        if event.is_directory or self._ignored(event.dest_path):
            return
        if self._ignored(event.src_path):  # e.g. temp file renamed to real file (saves in Word)
            logger.info("NEW_FILE | path=%s | via=rename-from-temp", event.dest_path)
        else:
            logger.info("FILE_MOVED | from=%s | to=%s", event.src_path, event.dest_path)


def start_file_watcher() -> Observer:
    observer = Observer()
    handler = NewFileHandler()
    for d in WATCH_DIRS:
        if d.exists():
            observer.schedule(handler, str(d), recursive=True)
            logger.info("WATCHING | %s", d)
        else:
            logger.warning("WATCH_SKIPPED (not found) | %s", d)
    observer.start()
    return observer


# ----------------------------------------------------------------------------
# 2) POWER ON / OFF DETECTION
# ----------------------------------------------------------------------------
def get_boot_time() -> datetime:
    ms = ctypes.windll.kernel32.GetTickCount64()
    return datetime.now() - timedelta(milliseconds=ms)


def query_power_events(since: datetime) -> list:
    """Read power-related events from the Windows System log via PowerShell."""
    ids = ",".join(str(i) for i in POWER_EVENT_IDS)
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"Get-WinEvent -FilterHashtable @{{LogName='System';Id={ids};"
        f"StartTime=[datetime]'{since.strftime('%Y-%m-%dT%H:%M:%S')}'}} | "
        "Select-Object RecordId,Id,@{n='T';e={$_.TimeCreated.ToString('s')}},Message | "
        "ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=60,
        ).stdout.strip()
    except Exception as e:
        logger.error("POWER_QUERY_FAILED | %s", e)
        return []
    if not out:
        return []
    data = json.loads(out)
    if isinstance(data, dict):  # PowerShell returns a bare object for a single result
        data = [data]
    return sorted(data, key=lambda e: e["RecordId"])


def power_monitor():
    state = load_state()
    last_record = state.get("last_power_record", 0)
    since = datetime.now() - timedelta(days=1)  # first-run lookback

    while not stop_event.is_set():
        for ev in query_power_events(since):
            if ev["RecordId"] <= last_record:
                continue
            last_record = ev["RecordId"]
            label = POWER_EVENT_IDS.get(ev["Id"], f"EVENT_{ev['Id']}")
            msg = (ev.get("Message") or "").strip().splitlines()
            detail = msg[0][:200] if msg else ""
            if ev["Id"] == 1074 and msg:
                detail = " ".join(l.strip() for l in msg[:3])[:300]
            logger.info("POWER | %s | event_time=%s | id=%s | %s", label, ev["T"], ev["Id"], detail)

        state = load_state()
        state["last_power_record"] = last_record
        save_state(state)
        since = datetime.now() - timedelta(days=1)
        stop_event.wait(POWER_POLL_SECONDS)


# Real-time shutdown/logoff notice (works while the script runs in a console session)
_HANDLER_TYPE = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)


@_HANDLER_TYPE
def _console_handler(ctrl_type):
    names = {2: "CONSOLE_CLOSED", 5: "USER_LOGOFF", 6: "SYSTEM_SHUTDOWN"}
    if ctrl_type in names:
        logger.info("POWER | %s detected in real time", names[ctrl_type])
        stop_event.set()
        return ctrl_type != 2
    return False


def register_shutdown_handler():
    try:
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_handler, True)
    except Exception as e:
        logger.warning("SHUTDOWN_HANDLER_UNAVAILABLE | %s", e)


# ----------------------------------------------------------------------------
# 3) MAIL SENT / NOT SENT + SIZE  (desktop Outlook via COM)
# ----------------------------------------------------------------------------
def _naive(dt):
    return dt.replace(tzinfo=None)


def mail_monitor():
    try:
        import pythoncom
        import win32com.client
    except ImportError:
        logger.error("MAIL_MONITOR_DISABLED | pywin32 not installed")
        return

    pythoncom.CoInitialize()
    try:
        ns = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        sent_folder = ns.GetDefaultFolder(5)    # olFolderSentMail
        outbox_folder = ns.GetDefaultFolder(4)  # olFolderOutbox
    except Exception as e:
        logger.error("MAIL_MONITOR_DISABLED | cannot connect to Outlook: %s", e)
        return

    logger.info("MAIL_MONITOR_STARTED | Outlook connected")
    last_seen = datetime.now()
    reported_stuck = set()

    while not stop_event.is_set():
        try:
            # --- successfully sent mail ---
            items = sent_folder.Items
            items.Sort("[SentOn]", True)  # newest first
            new_mails = []
            for item in items:
                try:
                    sent_on = _naive(item.SentOn)
                except Exception:
                    continue
                if sent_on <= last_seen:
                    break
                new_mails.append((sent_on, item))

            for sent_on, item in reversed(new_mails):
                extra = f" | subject={item.Subject}" if LOG_MAIL_SUBJECT else ""
                logger.info(
                    "MAIL_SENT | sent_at=%s | size_bytes=%s | recipients=%s | attachments=%s%s",
                    sent_on.strftime("%Y-%m-%d %H:%M:%S"),
                    item.Size,
                    item.Recipients.Count,
                    item.Attachments.Count,
                    extra,
                )
            if new_mails:
                last_seen = max(t for t, _ in new_mails)

            # --- mail stuck in Outbox (not sent) ---
            now = datetime.now()
            current_ids = set()
            for item in outbox_folder.Items:
                eid = item.EntryID
                current_ids.add(eid)
                age = (now - _naive(item.CreationTime)).total_seconds()
                if age > OUTBOX_STUCK_SECONDS and eid not in reported_stuck:
                    reported_stuck.add(eid)
                    logger.warning(
                        "MAIL_NOT_SENT | stuck in Outbox for %ds | size_bytes=%s",
                        int(age), item.Size,
                    )
            reported_stuck &= current_ids  # forget mails that left the Outbox

        except Exception as e:
            logger.error("MAIL_POLL_ERROR | %s", e)

        stop_event.wait(MAIL_POLL_SECONDS)

    pythoncom.CoUninitialize()


#------------------------------------------------------------
# LOG PARSER
#------------------------------------------------------------

def parse_log_file(file_path):
    records = []

    pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*\|\s*(?P<message>.*)$'
    )

    try:
        file = open(file_path, "r", encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return records

    with file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            match = pattern.match(line)

            if match:
                timestamp = match.group("timestamp")
                message = match.group("message")
            else:
                timestamp = None
                message = line

            parts = message.split(" | ", 1)
            event = parts[0]
            details = parts[1] if len(parts) > 1 else ""
            records.append({
                "timestamp": timestamp,
                "event": event,
                "details": details
            })

    return records[-200:]
# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------
def monitor():
    if os.name != "nt":
        raise RuntimeError("This monitor is designed for Windows.")

    logger.info("COLLECTOR_STARTED | system_boot_time=%s", get_boot_time().strftime("%Y-%m-%d %H:%M:%S"))
    register_shutdown_handler()
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    observer = start_file_watcher()
    threads = [
        threading.Thread(target=power_monitor, daemon=True, name="power"),
        threading.Thread(target=mail_monitor, daemon=True, name="mail"),
    ]
    for t in threads:
        t.start()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()
        logger.info("COLLECTOR_STOPPED")


if __name__ == "__main__":
    monitor()