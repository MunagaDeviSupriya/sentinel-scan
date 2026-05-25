"""
MCOGAN+ Live File Monitor  —  Windows-compatible
=================================================
Watches folders for new files and auto-scans them for malware.

Usage:
    python monitor.py                           # watches ~/Downloads
    python monitor.py --folder "C:/Users/munag/Downloads"
    python monitor.py --folder "C:/A" "C:/B"   # multiple folders

Requirements:
    pip install watchdog requests
"""

import argparse
import hashlib
import math
import os
import sys
import time
import threading
from collections import Counter
from datetime import datetime

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

# ── Config ────────────────────────────────────────────────────────────────────
BACKEND_URL  = "http://127.0.0.1:5000"
PREDICT_URL  = f"{BACKEND_URL}/predict"
MONITOR_URL  = f"{BACKEND_URL}/monitor_event"

SCAN_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".js",  ".jar", ".msi", ".scr", ".com", ".pif",
    ".zip", ".rar", ".7z",  ".tar", ".gz",
    ".doc", ".docx",".xls", ".xlsx",".pdf",
}

SKIP_EXTENSIONS = {
    ".crdownload", ".part", ".tmp", ".temp",
    ".download", ".partial", ".!ut",
}

MAX_WAIT_SECONDS  = 60    # increased from 30
STABLE_CHECK_SECS = 1.5   # check size every 1.5 seconds
STABLE_READS_NEEDED = 3   # need 3 consecutive same-size reads = truly stable

# ── Wait until file is stable ─────────────────────────────────────────────────
def wait_until_stable(filepath: str) -> bool:
    """
    Wait until file size is stable for STABLE_READS_NEEDED consecutive reads.
    More reliable than just 2 reads — handles slow downloads and large files.
    """
    deadline     = time.time() + MAX_WAIT_SECONDS
    prev_size    = -1
    stable_count = 0

    while time.time() < deadline:
        try:
            size = os.path.getsize(filepath)
        except OSError:
            # File temporarily gone (rename in progress) — wait and retry
            time.sleep(0.5)
            stable_count = 0
            prev_size    = -1
            continue

        if size == 0:
            # File exists but empty — still being created
            time.sleep(STABLE_CHECK_SECS)
            continue

        if size == prev_size:
            stable_count += 1
            if stable_count >= STABLE_READS_NEEDED:
                return True
        else:
            stable_count = 0

        prev_size = size
        time.sleep(STABLE_CHECK_SECS)

    # Timed out — check if file at least exists and has content
    try:
        return os.path.getsize(filepath) > 0
    except OSError:
        return False


# ── Feature extraction ────────────────────────────────────────────────────────
def file_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts  = Counter(data)
    length  = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features(filepath: str) -> dict:
    features = {
        "file_size":         0.0,
        "entropy_score":     0.0,
        "section_count":     0.0,
        "api_call_count":    0.0,
        "import_table_size": 0.0,
    }
    try:
        file_size = os.path.getsize(filepath)
        if file_size == 0:
            print(f"  [WARN] File is empty: {filepath}")
            return features

        features["file_size"] = float(file_size)

        with open(filepath, "rb") as f:
            raw = f.read(min(file_size, 4 * 1024 * 1024))

        if not raw:
            print(f"  [WARN] Could not read file contents: {filepath}")
            return features

        features["entropy_score"] = file_entropy(raw)

        ext = os.path.splitext(filepath)[1].lower()
        if ext in {".exe", ".dll", ".scr", ".com", ".pif", ".sys"}:
            try:
                import pefile
                pe = pefile.PE(filepath, fast_load=False)
                features["section_count"]     = float(len(pe.sections))
                features["import_table_size"] = float(
                    sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
                )
                features["api_call_count"] = features["import_table_size"]
                pe.close()
            except Exception:
                features["section_count"]     = float(raw.count(b"PE\x00\x00"))
                features["api_call_count"]    = float(raw.count(b".dll") + raw.count(b".DLL"))
                features["import_table_size"] = features["api_call_count"]
        else:
            features["api_call_count"]    = float(
                raw.count(b"CreateProcess") +
                raw.count(b"WriteFile") +
                raw.count(b"RegSetValue")
            )
            features["import_table_size"] = features["api_call_count"]

        print(f"  [INFO] Features: size={file_size}, entropy={features['entropy_score']:.2f}")

    except PermissionError:
        print(f"  [SKIP] Permission denied: {filepath}")
    except Exception as exc:
        print(f"  [WARN] Feature extraction error: {exc}")
    return features


def file_md5(filepath: str) -> str:
    h = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception:
        return "unknown"
    return h.hexdigest()


# ── Backend communication ─────────────────────────────────────────────────────
def scan_file(filepath: str):
    feats  = extract_features(filepath)
    vector = [
        feats["file_size"],
        feats["entropy_score"],
        feats["section_count"],
        feats["api_call_count"],
        feats["import_table_size"],
    ]

    # Check if all features are zero — no point sending to backend
    if all(v == 0.0 for v in vector):
        print(f"  [WARN] All features are zero — file may be unreadable or empty.")
        return None

    try:
        resp = requests.post(PREDICT_URL, json={"features": vector}, timeout=30)
        resp.raise_for_status()
        result = resp.json()

        # Check if backend returned a warning (all-zero features)
        if result.get("warning"):
            print(f"  [WARN] Backend warning: {result['warning']}")
            return None

        result["filepath"]  = filepath
        result["filename"]  = os.path.basename(filepath)
        result["md5"]       = file_md5(filepath)
        result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result["features"]  = feats
        return result

    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] Backend not reachable at {BACKEND_URL}. Is backend.py running?")
    except requests.exceptions.HTTPError as exc:
        # Print the actual error response from the server
        print(f"  [ERROR] Server error {exc.response.status_code}: {exc.response.text[:300]}")
    except Exception as exc:
        print(f"  [ERROR] Scan failed: {exc}")
    return None


def push_to_dashboard(result: dict):
    try:
        requests.post(MONITOR_URL, json=result, timeout=5)
    except Exception:
        pass


def print_result(result: dict):
    status = "MALICIOUS" if result.get("is_malicious") else "BENIGN"
    icon   = "🔴" if result.get("is_malicious") else "🟢"
    print(f"\n{'─'*56}")
    print(f"  FILE      : {result['filename']}")
    print(f"  RESULT    : {icon} {status}")
    print(f"  FAMILY    : {result.get('prediction', '?')}")
    print(f"  CONFIDENCE: {result.get('confidence', 0):.1f}%")
    print(f"  MD5       : {result['md5']}")
    print(f"  TIME      : {result['timestamp']}")
    print(f"{'─'*56}\n")


# ── File processor ────────────────────────────────────────────────────────────
class FileProcessor:
    def __init__(self):
        self._seen  = set()
        self._lock  = threading.Lock()

    def _normalise(self, path: str) -> str:
        return os.path.normcase(os.path.abspath(path))

    def submit(self, filepath: str):
        ext = os.path.splitext(filepath)[1].lower()
        if ext in SKIP_EXTENSIONS:
            return
        if ext not in SCAN_EXTENSIONS:
            return

        norm = self._normalise(filepath)
        with self._lock:
            if norm in self._seen:
                return
            self._seen.add(norm)

        threading.Thread(target=self._process, args=(filepath,), daemon=True).start()

    def _process(self, filepath: str):
        filename = os.path.basename(filepath)
        print(f"\n[+] Detected: {filename}")
        print(f"    Waiting for file to finish writing...")

        if not wait_until_stable(filepath):
            print(f"    [SKIP] File not ready or disappeared: {filename}")
            # Remove from seen so it can be retried
            with self._lock:
                self._seen.discard(self._normalise(filepath))
            return

        # Double-check file exists and has content
        try:
            size = os.path.getsize(filepath)
            if size == 0:
                print(f"    [SKIP] File is empty: {filename}")
                return
            print(f"    File ready: {size:,} bytes")
        except OSError:
            print(f"    [SKIP] File no longer accessible: {filename}")
            return

        # Re-check extension after any rename
        ext = os.path.splitext(filepath)[1].lower()
        if ext in SKIP_EXTENSIONS or ext not in SCAN_EXTENSIONS:
            print(f"    [SKIP] Extension not scannable: {ext}")
            return

        print(f"    Scanning {filename}...")
        result = scan_file(filepath)
        if result:
            print_result(result)
            push_to_dashboard(result)
        else:
            print(f"    [FAIL] Could not scan {filename}")


# ── Watchdog handler ──────────────────────────────────────────────────────────
class MonitorHandler(FileSystemEventHandler):
    def __init__(self, processor: FileProcessor):
        self._proc = processor

    def on_created(self, event):
        if not event.is_directory:
            self._proc.submit(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._proc.submit(event.dest_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._proc.submit(event.src_path)

    def on_closed(self, event):
        if not event.is_directory:
            self._proc.submit(event.src_path)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    default_folder = os.path.join(os.path.expanduser("~"), "Downloads")

    parser = argparse.ArgumentParser(description="MCOGAN+ Live File Monitor")
    parser.add_argument("--folder", nargs="+", default=[default_folder],
                        help="Folder(s) to monitor (default: ~/Downloads)")
    parser.add_argument("--recursive", action="store_true", default=False,
                        help="Also watch sub-folders")
    parser.add_argument("--polling", action="store_true", default=False,
                        help="Use polling observer (for USB/network drives)")
    args = parser.parse_args()

    folders = [os.path.abspath(f) for f in args.folder]
    for folder in folders:
        if not os.path.isdir(folder):
            print(f"[ERROR] Not a valid directory: {folder}")
            sys.exit(1)

    print("\n[*] Checking backend connection...")
    try:
        r = requests.get(f"{BACKEND_URL}/health", timeout=5)
        r.raise_for_status()
        print(f"[✓] Backend online at {BACKEND_URL}")
    except Exception:
        print(f"[!] WARNING: Backend not reachable at {BACKEND_URL}")
        print(f"    Make sure backend.py is running first.")
        print(f"    Monitor will keep trying on each scan...\n")

    processor     = FileProcessor()
    handler       = MonitorHandler(processor)
    ObserverClass = PollingObserver if args.polling else Observer
    observer      = ObserverClass()

    for folder in folders:
        observer.schedule(handler, folder, recursive=args.recursive)
        mode = "(recursive)" if args.recursive else "(top-level)"
        print(f"[*] Watching {mode}: {folder}")

    print(f"\n[*] Scanning : {', '.join(sorted(SCAN_EXTENSIONS))}")
    print(f"[*] Skipping : {', '.join(sorted(SKIP_EXTENSIONS))}")
    print(f"[*] Dashboard: open index.html in your browser")
    print(f"[*] Press Ctrl+C to stop\n")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping monitor...")
        observer.stop()
    observer.join()
    print("[*] Monitor stopped.")


if __name__ == "__main__":
    main()
