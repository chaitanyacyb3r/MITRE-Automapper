"""RansomGuard: behaviour-based ransomware detection on REAL file-system events.

Design (three layers, so each can be tested on its own):
  1. RansomDetector  - pure decision logic (no OS, no threads). Feed it events, it returns alerts.
  2. RansomGuard     - plugs the detector into the OS via `watchdog` file-system events.
  3. RansomSimulator - SAFE ransomware imitation: only touches files it creates itself inside a
                       temp folder (writes random bytes, renames to .locked). Lets you demo/test.

What it detects (behavioural signals, the same ideas EDR products use, in simplified form):
  * ENTROPY JUMP: a file's content goes from low entropy (text) to ~8 bits/byte (ciphertext).
  * EXTENSION CHANGE: files renamed to a known ransomware extension (.locked, .crypt ...).
  * VOLUME: many *distinct* files hit by those signals inside a short time window.
Known limits (say these in an interview): samples only the first 64 KB of a file; legitimately
compressed/encrypted files can look similar (mitigated by a baseline + a compressed-type allowlist);
user-space watchdog events can be missed under heavy I/O - real EDR uses kernel minifilters/ETW.
"""
import os
import shutil
import threading
import time
from collections import deque

from src.textutils import shannon_entropy

SAMPLE_BYTES = 64 * 1024                       # only read the head of a file: fast, bounded cost
RANSOM_EXTENSIONS = {".locked", ".crypt", ".crypted", ".enc", ".encrypted", ".wncry", ".wannacry", ".cryptor"}
COMPRESSED_EXTENSIONS = {".zip", ".gz", ".7z", ".rar", ".jpg", ".jpeg", ".png", ".mp4", ".mp3", ".pdf", ".docx", ".xlsx"}


def file_entropy(path, sample_bytes=SAMPLE_BYTES):
    """Entropy (bits/byte) of the first `sample_bytes` of a file, or None if unreadable.

    How: open in binary, read a bounded head, call shannon_entropy. Returns None (not an
    exception) when the file vanished or is locked, because files in a ransomware storm are
    renamed/deleted constantly and a monitoring thread must not crash on that.
    """
    try:
        with open(path, "rb") as f:
            return round(shannon_entropy(f.read(sample_bytes)), 2)
    except (OSError, PermissionError):
        return None


class RansomDetector:
    """Stateful decision engine: turns a stream of file events into alerts.

    Parameters
      window_sec        sliding window used to count distinct suspicious files
      min_files         distinct suspicious files inside the window needed for a CRITICAL alert
      entropy_threshold content at/above this (bits/byte) is 'ciphertext-like'
      entropy_jump      baseline->new rise required so already-high-entropy files don't trigger
    State: `baseline` (path -> last known entropy) and a deque of recent suspicious events.
    """

    def __init__(self, window_sec=5.0, min_files=5, entropy_threshold=7.2, entropy_jump=2.0):
        self.window_sec = window_sec
        self.min_files = min_files
        self.entropy_threshold = entropy_threshold
        self.entropy_jump = entropy_jump
        self.baseline = {}                 # file path -> entropy when we first/last saw it
        self.recent = deque()              # (timestamp, path) of suspicious events
        self.critical = False              # latched once a CRITICAL alert fired

    def learn_baseline(self, path, entropy):
        """Record a file's current entropy as 'normal' (called for pre-existing files at start)."""
        if entropy is not None:
            self.baseline[path] = entropy

    def _is_suspicious(self, path, entropy, ext):
        """Decide whether ONE event looks ransomware-like; returns (bool, reason).

        Rules, in order:
          a) extension is a known ransomware extension            -> suspicious
          b) entropy >= threshold AND rose >= entropy_jump vs the baseline -> suspicious
          c) entropy >= threshold, no baseline, extension is NOT a normally-compressed type -> suspicious
        Rule (b)/(c) are what stop zips/JPEGs from raising false alarms.
        """
        if ext.lower() in RANSOM_EXTENSIONS:
            return True, "ransomware-style extension"
        if entropy is None or entropy < self.entropy_threshold:
            return False, ""
        old = self.baseline.get(path)
        if old is not None:
            return (entropy - old >= self.entropy_jump), "entropy jump %.1f -> %.1f" % (old, entropy)
        if ext.lower() in COMPRESSED_EXTENSIONS:
            return False, ""
        return True, "new high-entropy file"

    def process(self, path, kind, entropy, now=None):
        """Feed one event; returns an alert dict (always) with the verdict filled in.

        `rate` = suspicious files seen in the sliding window (not per second, to stay
        robust to bursty I/O). severity: INFO (normal), WARNING (suspicious event),
        CRITICAL (>= min_files distinct suspicious files in the window).
        """
        now = time.time() if now is None else now
        ext = os.path.splitext(path)[1]
        suspicious, reason = self._is_suspicious(path, entropy, ext)

        while self.recent and now - self.recent[0][0] > self.window_sec:   # expire old events
            self.recent.popleft()
        if suspicious:
            self.recent.append((now, path))
        distinct = len({p for _, p in self.recent})

        severity = "INFO"
        if suspicious:
            severity = "WARNING"
        if distinct >= self.min_files:
            severity = "CRITICAL"
            self.critical = True
        if entropy is not None and not suspicious:
            self.baseline[path] = entropy              # benign edit: update what 'normal' is

        return {"timestamp": time.strftime("%H:%M:%S", time.localtime(now)), "event": kind,
                "file": os.path.basename(path), "entropy": entropy if entropy is not None else 0.0,
                "extension": ext or "None", "rate": distinct, "severity": severity, "reason": reason}


try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:                                    # keep module importable without watchdog
    FileSystemEventHandler = object
    Observer = None


class _Handler(FileSystemEventHandler):
    """watchdog callback class: converts OS events into RansomDetector.process() calls."""

    def __init__(self, detector, callback):
        """Store the detector (decision logic) and the user callback that receives alerts."""
        self.detector, self.callback = detector, callback

    def _handle(self, path, kind):
        """Measure entropy of `path` now, run the detector, forward the alert."""
        self.callback(self.detector.process(path, kind, file_entropy(path)))

    def on_modified(self, event):
        """Called by watchdog when a file's content changes."""
        if not event.is_directory:
            self._handle(event.src_path, "Modified")

    def on_created(self, event):
        """Called when a new file appears."""
        if not event.is_directory:
            self._handle(event.src_path, "Created")

    def on_moved(self, event):
        """Called on rename; ransomware typically renames file.docx -> file.docx.locked."""
        if not event.is_directory:
            self._handle(event.dest_path, "Renamed")


class RansomGuard:
    """Watches a real directory and reports alerts through a callback."""

    def __init__(self, watch_dir):
        """`watch_dir` must exist; a ValueError is raised otherwise (no silent fake mode any more)."""
        if not watch_dir or not os.path.isdir(watch_dir):
            raise ValueError("watch_dir must be an existing directory")
        self.watch_dir = watch_dir
        self.detector = RansomDetector()
        self.observer = None
        self.is_running = False

    def start_monitoring(self, alert_callback):
        """Snapshot baseline entropies of existing files, then start the watchdog observer thread."""
        if self.is_running:
            return
        if Observer is None:
            raise RuntimeError("watchdog is not installed (pip install watchdog)")
        for name in os.listdir(self.watch_dir):                 # baseline of 'normal'
            p = os.path.join(self.watch_dir, name)
            if os.path.isfile(p):
                self.detector.learn_baseline(p, file_entropy(p))
        self.observer = Observer()
        self.observer.schedule(_Handler(self.detector, alert_callback), self.watch_dir, recursive=False)
        self.observer.start()
        self.is_running = True

    def stop_monitoring(self):
        """Stop and join the observer thread (safe to call twice)."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.is_running = False


class RansomSimulator:
    """SAFE ransomware imitation for demos/tests. Touches ONLY files it created in `directory`."""

    def __init__(self, directory, n_files=30, benign_seconds=3.0, delay=0.05):
        """directory: sandbox folder; n_files: victim files; benign_seconds: normal-activity phase
        before the 'attack'; delay: pause between encrypted files."""
        self.directory, self.n_files = directory, n_files
        self.benign_seconds, self.delay = benign_seconds, delay
        self.thread = None
        self.finished = threading.Event()

    def create_victim_files(self):
        """Create text-like (low entropy, ~3-5 bits/byte) documents to be 'encrypted' later."""
        words = "quarterly report invoice customer salary backup budget meeting notes project".split()
        for i in range(self.n_files):
            body = " ".join(words[(i + j) % len(words)] for j in range(4000))
            with open(os.path.join(self.directory, "doc_%02d.txt" % i), "w") as f:
                f.write(body)

    def _run(self):
        """Phase 1: harmless text edits. Phase 2: overwrite each file with random bytes
        (os.urandom ~ what good ciphertext looks like, ~8 bits/byte) and rename to .locked."""
        end = time.time() + self.benign_seconds
        while time.time() < end:                                # normal user activity
            with open(os.path.join(self.directory, "doc_00.txt"), "a") as f:
                f.write(" edited note")
            time.sleep(0.4)
        for i in range(self.n_files):                           # the 'attack'
            path = os.path.join(self.directory, "doc_%02d.txt" % i)
            if not os.path.exists(path):
                continue
            size = os.path.getsize(path)
            with open(path, "wb") as f:
                f.write(os.urandom(max(size, 4096)))
            os.rename(path, path + ".locked")
            time.sleep(self.delay)
        self.finished.set()

    def start(self):
        """Run the simulation in a background daemon thread."""
        self.finished.clear()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def is_running(self):
        """True until the attack phase has completed."""
        return not self.finished.is_set()

    def cleanup(self):
        """Delete the sandbox folder (only ever a temp dir created by the caller)."""
        shutil.rmtree(self.directory, ignore_errors=True)


if __name__ == "__main__":
    import tempfile
    d = tempfile.mkdtemp(prefix="ransomguard_demo_")
    sim = RansomSimulator(d, n_files=20, benign_seconds=2)
    sim.create_victim_files()
    guard = RansomGuard(d)
    guard.start_monitoring(lambda a: print(a["timestamp"], a["severity"], a["file"], a["entropy"], a["reason"]))
    sim.start()
    sim.finished.wait()
    time.sleep(1)
    guard.stop_monitoring()
    sim.cleanup()
