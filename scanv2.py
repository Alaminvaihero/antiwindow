#!/usr/bin/env python3
"""
Terminal-based Antivirus Scanner for Windows 11/12 (Enhanced)
Developer: ALAMIN / MR VIRUS
Usage: python scan.py [directory] [--threads N] [--exclude DIR] [--report json|html]
"""

import os
import sys
import hashlib
import time
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Set, Generator

# Third-party imports with graceful fallback
try:
    import yara
except ImportError:
    yara = None
try:
    import pefile
except ImportError:
    pefile = None
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None
try:
    import psutil
except ImportError:
    psutil = None
try:
    import pyamsi
except ImportError:
    pyamsi = None

# Fallback console if rich not installed
if not RICH_AVAILABLE:
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
        def input(self, prompt):
            return input(prompt)

console = Console() if RICH_AVAILABLE else Console()

# ------------------------- Configuration -------------------------
RULES_DIR = Path("rules")
QUARANTINE_DIR = Path("quarantine")
HASH_DB_FILE = Path("malware_hashes.txt")
LOG_FILE = Path("scan_log.txt")
REPORT_DIR = Path("reports")
SCAN_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.ps1', '.vbs', '.js', '.bat', '.cmd', '.com', '.msi', '.jar', '.class'}
DEFAULT_IGNORE_DIRS = {
    "C:\\Windows", "C:\\System Volume Information", "$Recycle.Bin",
    "C:\\ProgramData\\Microsoft\\Windows\\WER", "C:\\Windows.old"
}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ------------------------- Helper Functions -------------------------
def setup_directories():
    """Create necessary directories"""
    QUARANTINE_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    RULES_DIR.mkdir(exist_ok=True)

def load_hash_database() -> tuple[Set[str], Set[str]]:
    """Load SHA256 and MD5 hash sets"""
    sha256_set = set()
    md5_set = set()
    if HASH_DB_FILE.exists():
        try:
            with open(HASH_DB_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip().lower()
                    if not line or line.startswith('#'):
                        continue
                    if len(line) == 64 and all(c in '0123456789abcdef' for c in line):
                        sha256_set.add(line)
                    elif len(line) == 32 and all(c in '0123456789abcdef' for c in line):
                        md5_set.add(line)
            console.print(f"[green]✓[/] Loaded {len(sha256_set)} SHA256 and {len(md5_set)} MD5 hashes.")
            logging.info(f"Hash DB loaded: {len(sha256_set)} SHA256, {len(md5_set)} MD5")
        except Exception as e:
            console.print(f"[red]✗[/] Failed to load hash DB: {e}")
            logging.error(f"Hash DB load error: {e}")
    else:
        console.print(f"[yellow]![/] Hash DB not found. Hash scanning disabled.")
    return sha256_set, md5_set

def compile_yara_rules():
    """Compile YARA rules from rules/ folder"""
    if yara is None:
        console.print("[yellow]![/] yara-python not installed. YARA scanning disabled.")
        return None
    rule_files = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
    if not rule_files:
        console.print("[yellow]![/] No YARA rules found.")
        return None
    try:
        filepaths = {str(f): str(f) for f in rule_files}
        rules = yara.compile(filepaths=filepaths)
        console.print(f"[green]✓[/] Loaded {len(rule_files)} YARA rule files.")
        return rules
    except Exception as e:
        console.print(f"[red]✗[/] YARA compile error: {e}")
        logging.error(f"YARA error: {e}")
        return None

def calculate_hashes(filepath: Path) -> Dict[str, str]:
    """Calculate MD5, SHA1, SHA256"""
    hashes = {'md5': '', 'sha1': '', 'sha256': ''}
    try:
        with open(filepath, 'rb') as f:
            data = f.read(MAX_FILE_SIZE)  # Read only up to 100MB
            if len(data) == MAX_FILE_SIZE:
                # If file larger, read whole but careful
                f.seek(0)
                data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
    except (PermissionError, OSError) as e:
        logging.warning(f"Cannot read {filepath}: {e}")
    except Exception as e:
        logging.error(f"Hash error {filepath}: {e}")
    return hashes

def quarantine_file(filepath: Path, reason: str) -> Optional[Path]:
    """Move file to quarantine with metadata"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        dest = QUARANTINE_DIR / f"{timestamp}_{filepath.name}"
        os.rename(str(filepath), str(dest))
        # Save metadata
        meta = {
            "original_path": str(filepath),
            "quarantined_at": datetime.now().isoformat(),
            "reason": reason,
            "file_size": filepath.stat().st_size if filepath.exists() else 0
        }
        with open(dest.with_suffix(".meta.json"), 'w') as f:
            json.dump(meta, f, indent=2)
        logging.info(f"Quarantined: {filepath} -> {dest} ({reason})")
        return dest
    except Exception as e:
        console.print(f"[red]Quarantine failed {filepath}: {e}[/]")
        logging.error(f"Quarantine error {filepath}: {e}")
        return None

def is_excluded(path: Path, exclude_dirs: Set[str]) -> bool:
    """Check if path should be excluded"""
    path_str = str(path.resolve())
    for excl in exclude_dirs:
        if path_str.startswith(excl):
            return True
    return False

def scan_with_yara(filepath: Path) -> List[str]:
    """YARA scan"""
    if yara_rules is None or yara is None:
        return []
    try:
        matches = yara_rules.match(str(filepath), timeout=30)
        return [str(m.rule) for m in matches]
    except Exception as e:
        logging.debug(f"YARA error on {filepath}: {e}")
        return []

def scan_with_amsi(filepath: Path) -> bool:
    """AMSI scan (Windows only)"""
    if pyamsi is None or sys.platform != "win32":
        return False
    try:
        amsi = pyamsi.Amsi()
        with open(filepath, 'rb') as f:
            content = f.read()
        result = amsi.scan_buffer(content, filepath.name)
        return result == 1
    except Exception:
        return False

def check_suspicious_pe(filepath: Path) -> List[str]:
    """PE file analysis"""
    if pefile is None or filepath.suffix.lower() != '.exe':
        return []
    warnings = []
    try:
        pe = pefile.PE(str(filepath))
        # Packer signatures
        packers = ['.upx', '.aspack', '.mpress', '.upack', '.nspack']
        for section in pe.sections:
            name = section.Name.decode().rstrip('\x00').lower()
            if name in packers:
                warnings.append(f"Packed:{name}")
        # Suspicious imports
        suspicious = [b'VirtualAlloc', b'WriteProcessMemory', b'CreateRemoteThread',
                      b'WinExec', b'ShellExecute', b'CryptAcquireContext']
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name in suspicious:
                        warnings.append(f"API:{imp.name.decode()}")
        pe.close()
    except Exception:
        pass
    return warnings

def scan_file(filepath: Path, sha256_set: Set[str], md5_set: Set[str]) -> Optional[Dict]:
    """Single file scan"""
    if not filepath.is_file():
        return None
    if filepath.suffix.lower() not in SCAN_EXTENSIONS:
        return None
    if filepath.stat().st_size > MAX_FILE_SIZE * 2:  # >200MB skip
        return None

    threats = []
    details = {}

    # Hash scan
    hashes = calculate_hashes(filepath)
    if hashes['sha256'] in sha256_set:
        threats.append("Hash:SHA256")
    if hashes['md5'] in md5_set:
        threats.append("Hash:MD5")
    if threats:
        details['hash_match'] = True

    # YARA
    yara_hits = scan_with_yara(filepath)
    if yara_hits:
        threats.extend([f"YARA:{h}" for h in yara_hits])
        details['yara'] = yara_hits

    # AMSI
    if scan_with_amsi(filepath):
        threats.append("AMSI:Malicious")
        details['amsi'] = True

    # PE heuristics
    pe_warns = check_suspicious_pe(filepath)
    if pe_warns:
        details['pe_warnings'] = pe_warns
        # Don't mark as threat just for packer, but suspicious
        if not threats:
            threats.append("Suspicious:PE")
    else:
        if pe_warns:
            threats.append("Heuristic:PE")

    if threats:
        return {
            'path': str(filepath),
            'threats': threats,
            'details': details,
            'hashes': hashes
        }
    return None

def walk_files(root_dir: Path, exclude_dirs: Set[str]) -> Generator[Path, None, None]:
    """Generator to yield files without loading all into memory"""
    try:
        for entry in root_dir.rglob('*'):
            if entry.is_file() and not is_excluded(entry, exclude_dirs):
                yield entry
    except (PermissionError, OSError):
        pass

def scan_directory(root_dir: Path, exclude_dirs: Set[str], max_workers: int,
                   sha256_set: Set[str], md5_set: Set[str],
                   progress, task_id) -> List[Dict]:
    """Multi-threaded scan"""
    findings = []
    files = list(walk_files(root_dir, exclude_dirs))
    total = len(files)
    progress.update(task_id, total=total)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(scan_file, f, sha256_set, md5_set): f for f in files}
        for future in as_completed(future_to_file):
            progress.advance(task_id)
            try:
                result = future.result()
                if result:
                    findings.append(result)
                    threat_str = ", ".join(result['threats'])
                    console.print(f"[bold red]🚨 THREAT:[/] {Path(result['path']).name}")
                    console.print(f"   └─ [yellow]{threat_str}[/]")
            except Exception as e:
                logging.error(f"Scan error: {e}")
    return findings

def generate_report(findings: List[Dict], scan_root: str, start_time: float, format: str = "text"):
    """Generate report in JSON or HTML"""
    elapsed = time.time() - start_time
    report_data = {
        "scan_time": datetime.now().isoformat(),
        "target": scan_root,
        "duration_seconds": elapsed,
        "total_threats": len(findings),
        "threats": findings
    }
    if format == "json":
        report_file = REPORT_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        console.print(f"[green]✓ JSON report saved: {report_file}[/]")
    elif format == "html":
        report_file = REPORT_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html = f"""<!DOCTYPE html>
        <html><head><meta charset="UTF-8"><title>Antivirus Report</title>
        <style>body{{font-family:monospace;}} .threat{{color:red;}}</style></head>
        <body><h1>Scan Report</h1><p>Target: {scan_root}</p>
        <p>Duration: {elapsed:.2f}s</p><p>Threats found: {len(findings)}</p>
        <ul>"""
        for f in findings:
            html += f"<li class='threat'>{f['path']} - {', '.join(f['threats'])}</li>"
        html += "</ul></body></html>"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
        console.print(f"[green]✓ HTML report saved: {report_file}[/]")
    return report_data

def display_summary(findings: List[Dict], start_time: float, args):
    """Show final summary table"""
    elapsed = time.time() - start_time
    console.print("\n")
    title = Text(" SCAN COMPLETE ", style="bold white on blue")
    console.print(Panel(title, expand=False))

    if findings:
        if RICH_AVAILABLE:
            table = Table(title="Detected Threats", show_header=True, header_style="bold magenta")
            table.add_column("File", style="cyan", width=50)
            table.add_column("Threats", style="red")
            for f in findings:
                table.add_row(Path(f['path']).name, ", ".join(f['threats']))
            console.print(table)
        else:
            for f in findings:
                console.print(f"{f['path']} -> {', '.join(f['threats'])}")

        if console.input("\n[bold]Quarantine all? (y/n): [/]").lower() == 'y':
            for f in findings:
                qpath = quarantine_file(Path(f['path']), ", ".join(f['threats']))
                if qpath:
                    console.print(f"[green]✓ Quarantined:[/] {f['path']}")
    else:
        console.print("[green bold]✓ No threats detected.[/]")

    console.print(f"\n[dim]Time: {elapsed:.2f} sec | Threads: {args.threads}[/]")
    logging.info(f"Scan finished. Threats: {len(findings)}")

# ------------------------- Main Entry -------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(description="Terminal Antivirus Scanner")
    parser.add_argument("directory", nargs="?", default=str(Path.home()), help="Directory to scan")
    parser.add_argument("--threads", type=int, default=4, help="Number of scan threads (default 4)")
    parser.add_argument("--exclude", nargs="*", default=[], help="Additional directories to exclude")
    parser.add_argument("--report", choices=["text", "json", "html"], default="text", help="Report format")
    parser.add_argument("--no-rich", action="store_true", help="Disable rich output")
    return parser.parse_args()

def main():
    args = parse_arguments()
    if args.no_rich:
        global RICH_AVAILABLE, console
        RICH_AVAILABLE = False
        console = Console()  # fallback

    console.print(BANNER, style="bold cyan")
    setup_directories()

    # Load databases
    sha256_set, md5_set = load_hash_database()
    global yara_rules
    yara_rules = compile_yara_rules()

    # Exclude directories
    exclude_dirs = set(DEFAULT_IGNORE_DIRS)
    for excl in args.exclude:
        exclude_dirs.add(str(Path(excl).resolve()))

    scan_root = Path(args.directory)
    if not scan_root.exists():
        console.print(f"[red]Error: Directory '{scan_root}' does not exist.[/]")
        sys.exit(1)

    console.print(f"[cyan]Scanning: {scan_root}[/]")
    console.print(f"[dim]Excluding: {', '.join(exclude_dirs)}[/]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
        disable=not RICH_AVAILABLE
    ) as progress:
        task = progress.add_task("[cyan]Preparing scan...", total=None)
        start_time = time.time()
        findings = scan_directory(scan_root, exclude_dirs, args.threads,
                                  sha256_set, md5_set, progress, task)

    if args.report != "text":
        generate_report(findings, str(scan_root), start_time, args.report)

    display_summary(findings, start_time, args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/]")
        logging.info("Scan interrupted by user")
        sys.exit(0)