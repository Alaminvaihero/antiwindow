#!/usr/bin/env python3
"""
Terminal Antivirus Scanner for Windows (No Library Crash)
Developer: ALAMIN / MR VIRUS
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

# ========== Optional Imports with Fallback ==========
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
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
    # Fallback dummy classes
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
        def input(self, prompt):
            return input(prompt)
    class Table: pass
    class Progress: pass
    class Panel: pass
    class Text: pass

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import pyamsi
    AMSI_AVAILABLE = True
except ImportError:
    AMSI_AVAILABLE = False
    pyamsi = None

console = Console() if RICH_AVAILABLE else Console()

# ========== Configuration ==========
RULES_DIR = Path("rules")
QUARANTINE_DIR = Path("quarantine")
HASH_DB_FILE = Path("malware_hashes.txt")
LOG_FILE = Path("scan_log.txt")
REPORT_DIR = Path("reports")
SCAN_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.ps1', '.vbs', '.js', '.bat', '.cmd', '.com', '.msi', '.jar'}
DEFAULT_IGNORE_DIRS = {
    "C:\\Windows", "C:\\System Volume Information", "$Recycle.Bin",
    "C:\\ProgramData\\Microsoft\\Windows\\WER"
}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ========== Helper Functions ==========
def setup_directories():
    QUARANTINE_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    RULES_DIR.mkdir(exist_ok=True)

def load_hash_database() -> tuple[Set[str], Set[str]]:
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
            console.print(f"[green]✓[/] Loaded {len(sha256_set)} SHA256, {len(md5_set)} MD5 hashes")
        except Exception as e:
            console.print(f"[red]✗ Hash DB error: {e}")
    else:
        console.print("[yellow]! No malware_hashes.txt - hash scan disabled[/]")
    return sha256_set, md5_set

def compile_yara_rules():
    if not YARA_AVAILABLE:
        console.print("[yellow]! yara-python not installed - YARA disabled[/]")
        return None
    rule_files = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
    if not rule_files:
        console.print("[yellow]! No YARA rules in 'rules/' folder[/]")
        return None
    try:
        filepaths = {str(f): str(f) for f in rule_files}
        rules = yara.compile(filepaths=filepaths)
        console.print(f"[green]✓ Loaded {len(rule_files)} YARA rules[/]")
        return rules
    except Exception as e:
        console.print(f"[red]✗ YARA compile error: {e}[/]")
        return None

def calculate_hashes(filepath: Path) -> Dict[str, str]:
    hashes = {'md5': '', 'sha1': '', 'sha256': ''}
    try:
        with open(filepath, 'rb') as f:
            data = f.read(MAX_FILE_SIZE)
            # If file is larger than limit, still read whole (but careful)
            if len(data) == MAX_FILE_SIZE:
                f.seek(0)
                data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
    except (PermissionError, OSError):
        pass
    except Exception as e:
        logging.debug(f"Hash error {filepath}: {e}")
    return hashes

def quarantine_file(filepath: Path, reason: str) -> Optional[Path]:
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        dest = QUARANTINE_DIR / f"{timestamp}_{filepath.name}"
        os.rename(str(filepath), str(dest))
        meta = {
            "original_path": str(filepath),
            "quarantined_at": datetime.now().isoformat(),
            "reason": reason
        }
        with open(dest.with_suffix(".meta.json"), 'w') as f:
            json.dump(meta, f, indent=2)
        logging.info(f"Quarantined: {filepath}")
        return dest
    except Exception as e:
        console.print(f"[red]Quarantine failed {filepath.name}: {e}[/]")
        return None

def is_excluded(path: Path, exclude_dirs: Set[str]) -> bool:
    path_str = str(path.resolve())
    for excl in exclude_dirs:
        if path_str.startswith(excl):
            return True
    return False

def scan_with_yara(filepath: Path) -> List[str]:
    if not YARA_AVAILABLE or yara_rules is None:
        return []
    try:
        matches = yara_rules.match(str(filepath), timeout=30)
        return [str(m.rule) for m in matches]
    except Exception:
        return []

def scan_with_amsi(filepath: Path) -> bool:
    if not AMSI_AVAILABLE or sys.platform != "win32":
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
    if not PEFILE_AVAILABLE or filepath.suffix.lower() != '.exe':
        return []
    warnings = []
    try:
        pe = pefile.PE(str(filepath))
        packers = ['.upx', '.aspack', '.mpress', '.upack']
        for section in pe.sections:
            name = section.Name.decode().rstrip('\x00').lower()
            if name in packers:
                warnings.append(f"Packed:{name}")
        suspicious_apis = [b'VirtualAlloc', b'WriteProcessMemory', b'CreateRemoteThread', b'WinExec']
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name in suspicious_apis:
                        warnings.append(f"API:{imp.name.decode()}")
        pe.close()
    except Exception:
        pass
    return warnings

def scan_file(filepath: Path, sha256_set: Set[str], md5_set: Set[str]) -> Optional[Dict]:
    if not filepath.is_file():
        return None
    if filepath.suffix.lower() not in SCAN_EXTENSIONS:
        return None
    if filepath.stat().st_size > MAX_FILE_SIZE * 2:
        return None

    threats = []
    details = {}

    # Hash scan (always available)
    hashes = calculate_hashes(filepath)
    if hashes['sha256'] in sha256_set:
        threats.append("Hash:SHA256")
    if hashes['md5'] in md5_set:
        threats.append("Hash:MD5")
    if threats:
        details['hash_match'] = True

    # YARA (if available)
    yara_hits = scan_with_yara(filepath)
    if yara_hits:
        threats.extend([f"YARA:{h}" for h in yara_hits])
        details['yara'] = yara_hits

    # AMSI (if available)
    if scan_with_amsi(filepath):
        threats.append("AMSI:Malicious")
        details['amsi'] = True

    # PE heuristics (if available)
    pe_warns = check_suspicious_pe(filepath)
    if pe_warns:
        details['pe_warnings'] = pe_warns
        if not threats:
            threats.append("Suspicious:PE")

    if threats:
        return {
            'path': str(filepath),
            'threats': threats,
            'details': details,
            'hashes': hashes
        }
    return None

def walk_files(root_dir: Path, exclude_dirs: Set[str]) -> Generator[Path, None, None]:
    try:
        for entry in root_dir.rglob('*'):
            if entry.is_file() and not is_excluded(entry, exclude_dirs):
                yield entry
    except (PermissionError, OSError):
        pass

def scan_directory(root_dir: Path, exclude_dirs: Set[str], max_workers: int,
                   sha256_set: Set[str], md5_set: Set[str],
                   progress, task_id) -> List[Dict]:
    files = list(walk_files(root_dir, exclude_dirs))
    total = len(files)
    progress.update(task_id, total=total)

    findings = []
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
        console.print(f"[green]✓ JSON report: {report_file}[/]")
    elif format == "html":
        report_file = REPORT_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html = f"""<html><head><meta charset="UTF-8"><title>Scan Report</title>
        <style>body{{font-family:monospace;}} .threat{{color:red;}}</style></head>
        <body><h1>Antivirus Report</h1><p>Target: {scan_root}</p>
        <p>Duration: {elapsed:.2f}s</p><p>Threats: {len(findings)}</p><ul>"""
        for f in findings:
            html += f"<li class='threat'>{f['path']} - {', '.join(f['threats'])}</li>"
        html += "</ul></body></html>"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
        console.print(f"[green]✓ HTML report: {report_file}[/]")
    return report_data

def display_summary(findings: List[Dict], start_time: float, args):
    elapsed = time.time() - start_time
    console.print("\n")
    if RICH_AVAILABLE:
        title = Text(" SCAN COMPLETE ", style="bold white on blue")
        console.print(Panel(title, expand=False))
    else:
        console.print("========== SCAN COMPLETE ==========")

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
                console.print(f"[THREAT] {f['path']} -> {', '.join(f['threats'])}")

        if console.input("\nQuarantine all? (y/n): ").lower() == 'y':
            for f in findings:
                qpath = quarantine_file(Path(f['path']), ", ".join(f['threats']))
                if qpath:
                    console.print(f"[green]✓ Quarantined: {f['path']}[/]")
    else:
        console.print("[green]✓ No threats detected.[/]")

    console.print(f"\nTime: {elapsed:.2f}s | Threads: {args.threads}")
    # Show which features were disabled
    disabled = []
    if not YARA_AVAILABLE: disabled.append("YARA")
    if not PEFILE_AVAILABLE: disabled.append("PE")
    if not AMSI_AVAILABLE: disabled.append("AMSI")
    if not RICH_AVAILABLE: disabled.append("RichUI")
    if disabled:
        console.print(f"[dim]Disabled features: {', '.join(disabled)}[/]")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Windows Antivirus Scanner")
    parser.add_argument("directory", nargs="?", default=str(Path.home()), help="Directory to scan")
    parser.add_argument("--threads", type=int, default=4, help="Thread count (default 4)")
    parser.add_argument("--exclude", nargs="*", default=[], help="Extra folders to exclude")
    parser.add_argument("--report", choices=["text", "json", "html"], default="text", help="Report format")
    return parser.parse_args()

# ========== Main ==========
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║   █████╗ ██╗      █████╗ ███╗   ███╗██╗███╗   ██╗          ║
║  ██╔══██╗██║     ██╔══██╗████╗ ████║██║████╗  ██║          ║
║  ███████║██║     ███████║██╔████╔██║██║██╔██╗ ██║          ║
║  ██╔══██║██║     ██╔══██║██║╚██╔╝██║██║██║╚██╗██║          ║
║  ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║          ║
║  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝          ║
║                   MR VIRUS TERMINAL ANTIVIRUS               ║
║            (No Library Crash - Windows Optimized)           ║
╚══════════════════════════════════════════════════════════════╝
"""

def main():
    args = parse_arguments()
    console.print(BANNER, style="bold cyan")
    setup_directories()

    # Show missing libraries warning (but continue)
    if not YARA_AVAILABLE:
        console.print("[yellow]⚠ yara-python missing → YARA scan disabled[/]")
    if not PEFILE_AVAILABLE:
        console.print("[yellow]⚠ pefile missing → PE heuristics disabled[/]")
    if not AMSI_AVAILABLE:
        console.print("[yellow]⚠ pyamsi missing → AMSI scan disabled[/]")
    if not RICH_AVAILABLE:
        console.print("[yellow]⚠ rich missing → using basic console[/]")

    sha256_set, md5_set = load_hash_database()
    global yara_rules
    yara_rules = compile_yara_rules()

    exclude_dirs = set(DEFAULT_IGNORE_DIRS)
    for excl in args.exclude:
        exclude_dirs.add(str(Path(excl).resolve()))

    scan_root = Path(args.directory)
    if not scan_root.exists():
        console.print(f"[red]Error: '{scan_root}' not found[/]")
        sys.exit(1)

    console.print(f"[cyan]Scanning: {scan_root}[/]")
    console.print(f"[dim]Excluded: {len(exclude_dirs)} folders[/]")

    # Progress bar (fallback if rich not available)
    if RICH_AVAILABLE:
        progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                            BarColumn(), TaskProgressColumn(), console=console, transient=True)
    else:
        progress = None
        console.print("Scanning... (no progress bar)")

    if progress:
        with progress:
            task = progress.add_task("[cyan]Scanning...", total=None)
            start_time = time.time()
            findings = scan_directory(scan_root, exclude_dirs, args.threads,
                                      sha256_set, md5_set, progress, task)
    else:
        start_time = time.time()
        # Manual scan without progress bar
        files = list(walk_files(scan_root, exclude_dirs))
        console.print(f"Total files: {len(files)}")
        findings = []
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(scan_file, f, sha256_set, md5_set) for f in files]
            for i, future in enumerate(as_completed(futures)):
                if i % 100 == 0:
                    console.print(f"Progress: {i}/{len(files)}")
                try:
                    res = future.result()
                    if res:
                        findings.append(res)
                except Exception:
                    pass

    if args.report != "text":
        generate_report(findings, str(scan_root), start_time, args.report)

    display_summary(findings, start_time, args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/]")
        sys.exit(0)