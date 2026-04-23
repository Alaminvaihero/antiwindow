#!/usr/bin/env python3
"""
Terminal-based Antivirus Scanner for Windows 11/12 (WSL-Compatible)
Developer: ALAMIN / MR VIRUS
Usage: python scan.py [directory_to_scan]
"""

import os
import sys
import hashlib
import time
from pathlib import Path
from datetime import datetime

try:
    import yara
    import pefile
    import psutil
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.text import Text
except ImportError as e:
    print(f"Missing required library: {e}")
    print("Please run: pip install yara-python pefile rich psutil")
    sys.exit(1)

console = Console()

# -------------------------------------------------------------------
# ব্যানার ও ডেভেলপার তথ্য
# -------------------------------------------------------------------
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   █████╗ ██╗      █████╗ ███╗   ███╗██╗███╗   ██╗          ║
║  ██╔══██╗██║     ██╔══██╗████╗ ████║██║████╗  ██║          ║
║  ███████║██║     ███████║██╔████╔██║██║██╔██╗ ██║          ║
║  ██╔══██║██║     ██╔══██║██║╚██╔╝██║██║██║╚██╗██║          ║
║  ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║          ║
║  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝          ║
║                                                              ║
║              MR VIRUS TERMINAL ANTIVIRUS SCANNER             ║
║                                                              ║
║  Developer: ALAMIN / MR VIRUS                                ║
║  TikTok   : @mr_virus_apk                                    ║
║  Facebook : Mohammad Alamin                                  ║
║  Instagram: @mr_virus_apk                                    ║
║  GitHub   : Alaminvaihero                                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

# -------------------------------------------------------------------
# কনফিগারেশন - MULTIPLE SEARCH LOCATIONS
# -------------------------------------------------------------------
SEARCH_PATHS = [
    Path("rules"),
    Path(os.path.expanduser("~/Desktop")),
    Path(".")
]

QUARANTINE_DIR = Path("quarantine")
SCAN_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.ps1', '.vbs', '.js', '.bat', '.cmd', '.com', '.msi'}

# -------------------------------------------------------------------
# Load hash database from all possible locations
# -------------------------------------------------------------------
def load_hash_database():
    sha256_set = set()
    md5_set = set()
    found_any = False
    
    for search_path in SEARCH_PATHS:
        hash_file = search_path / "malware_hashes.txt"
        if hash_file.exists():
            found_any = True
            try:
                with open(hash_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if len(line) == 64 and all(c in '0123456789abcdefABCDEF' for c in line):
                            sha256_set.add(line.lower())
                        elif len(line) == 32 and all(c in '0123456789abcdefABCDEF' for c in line):
                            md5_set.add(line.lower())
                console.print(f"[green]✓[/] Loaded hashes from {hash_file}")
            except Exception as e:
                console.print(f"[red]✗[/] Failed to read {hash_file}: {e}")
    
    if not found_any:
        console.print(f"[yellow]![/] No 'malware_hashes.txt' found in any search path. Hash scanning disabled.")
    else:
        console.print(f"[green]✓[/] Total loaded: {len(sha256_set)} SHA256 and {len(md5_set)} MD5 hashes.")
    
    return sha256_set, md5_set

sha256_hashes, md5_hashes = load_hash_database()

# -------------------------------------------------------------------
# Compile YARA rules from all possible locations
# -------------------------------------------------------------------
def compile_yara_rules():
    rule_files = []
    for search_path in SEARCH_PATHS:
        if search_path.exists():
            rule_files.extend(search_path.glob("*.yar"))
            rule_files.extend(search_path.glob("*.yara"))
    
    if not rule_files:
        console.print("[yellow]![/] No YARA rules found in any search path.")
        return None
    
    rule_files = list(set(rule_files))
    
    try:
        filepaths = {str(f): str(f) for f in rule_files}
        rules = yara.compile(filepaths=filepaths)
        console.print(f"[green]✓[/] Loaded YARA rules from {len(rule_files)} file(s).")
        return rules
    except Exception as e:
        console.print(f"[red]✗[/] Failed to compile YARA rules: {e}")
        return None

yara_rules = compile_yara_rules()

# -------------------------------------------------------------------
# Quarantine folder
# -------------------------------------------------------------------
QUARANTINE_DIR.mkdir(exist_ok=True)

# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------
def calculate_hashes(filepath):
    hashes = {'md5': '', 'sha1': '', 'sha256': ''}
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
    except Exception:
        pass
    return hashes

def quarantine_file(filepath):
    try:
        dest = QUARANTINE_DIR / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{Path(filepath).name}"
        os.rename(filepath, dest)
        return str(dest)
    except Exception as e:
        console.print(f"[red]Failed to quarantine {filepath}: {e}[/]")
        return None

# -------------------------------------------------------------------
# Scanning methods (AMSI removed)
# -------------------------------------------------------------------
def scan_with_yara(filepath):
    if yara_rules is None:
        return []
    try:
        matches = yara_rules.match(str(filepath), timeout=60)
        return [str(m.rule) for m in matches]
    except yara.TimeoutError:
        return ["[TIMEOUT]"]
    except Exception:
        return []

def check_suspicious_pe(filepath):
    if not filepath.suffix.lower() == '.exe':
        return []
    warnings = []
    try:
        pe = pefile.PE(filepath)
        suspicious_sections = ['.upx', '.aspack', '.mpress']
        for section in pe.sections:
            name = section.Name.decode().rstrip('\x00')
            if name in suspicious_sections:
                warnings.append(f"Packed: {name}")
        suspicious_apis = [b'VirtualAlloc', b'WriteProcessMemory', b'CreateRemoteThread', b'WinExec']
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name in suspicious_apis:
                        warnings.append(f"Suspicious API: {imp.name.decode()}")
    except:
        pass
    return warnings

# -------------------------------------------------------------------
# Main scan logic
# -------------------------------------------------------------------
def scan_file(filepath):
    filepath = Path(filepath)
    if not filepath.is_file():
        return None

    threats = []
    details = {}

    if filepath.suffix.lower() not in SCAN_EXTENSIONS:
        return None

    file_hashes = calculate_hashes(filepath)
    details['hashes'] = file_hashes
    
    hash_matches = []
    if file_hashes['sha256'] in sha256_hashes:
        hash_matches.append("SHA256")
    if file_hashes['md5'] in md5_hashes:
        hash_matches.append("MD5")
    
    if hash_matches:
        threats.append(f"Malware hash match ({', '.join(hash_matches)})")
        details['hash_match'] = hash_matches

    yara_hits = scan_with_yara(filepath)
    if yara_hits:
        threats.extend(yara_hits)
        details['yara'] = yara_hits

    pe_warnings = check_suspicious_pe(filepath)
    if pe_warnings:
        details['pe_warnings'] = pe_warnings

    if threats or pe_warnings:
        return {
            'path': filepath,
            'threats': threats,
            'details': details
        }
    return None

def scan_directory(root_dir, progress, task_id):
    findings = []
    all_files = list(Path(root_dir).rglob('*'))
    total_files = sum(1 for f in all_files if f.is_file())
    scanned_files = 0

    for filepath in all_files:
        if not filepath.is_file():
            continue
        scanned_files += 1
        progress.update(task_id, advance=1, description=f"[cyan]Scanning: {filepath.name[:30]}...")

        result = scan_file(filepath)
        if result:
            findings.append(result)
            threat_str = ", ".join(result['threats']) if result['threats'] else "Suspicious PE"
            console.print(f"[bold red]🚨 THREAT DETECTED:[/] {filepath}")
            console.print(f"   └─ [yellow]{threat_str}[/]")

    return findings

# -------------------------------------------------------------------
# Report display
# -------------------------------------------------------------------
def display_summary(findings, start_time):
    elapsed = time.time() - start_time

    console.print("\n")
    title = Text(" SCAN REPORT ", style="bold white on blue")
    console.print(Panel(title, expand=False))

    if findings:
        table = Table(title="Detected Threats", show_header=True, header_style="bold magenta")
        table.add_column("File Path", style="cyan", no_wrap=False, width=50)
        table.add_column("Threat Type", style="red")
        table.add_column("Details", style="yellow")

        for f in findings:
            path_str = str(f['path'])
            threat_str = ", ".join(f['threats']) if f['threats'] else "Suspicious Indicators"
            details_str = ""
            if 'hash_match' in f['details']:
                details_str = f"Hash ({', '.join(f['details']['hash_match'])})"
            elif 'yara' in f['details']:
                details_str = f"YARA: {', '.join(f['details']['yara'])}"
            elif 'pe_warnings' in f['details']:
                details_str = ", ".join(f['details']['pe_warnings'])
            table.add_row(path_str, threat_str, details_str)
        console.print(table)

        if console.input("\n[bold]Quarantine all detected files? (y/n): [/]").lower() == 'y':
            for f in findings:
                qpath = quarantine_file(f['path'])
                if qpath:
                    console.print(f"[green]✓ Quarantined:[/] {f['path']} -> {qpath}")
    else:
        console.print("[green bold]✓ No threats detected.[/]")

    console.print(f"\n[dim]Scan completed in {elapsed:.2f} seconds.[/]")

# -------------------------------------------------------------------
# Entry point – defaults to full system scan (C:\ on Windows, /mnt/c/ on WSL)
# -------------------------------------------------------------------
def main():
    console.print(BANNER, style="bold cyan")

    # Determine scan target
    if len(sys.argv) > 1:
        scan_root = Path(sys.argv[1])
    else:
        # Default: try to detect Windows system drive (works in WSL via /mnt/c/)
        if sys.platform == "win32":
            system_drive = os.environ.get('SystemDrive', 'C:')
            scan_root = Path(f"{system_drive}\\")
        else:
            # Check if running under WSL (Linux with /mnt/c/ present)
            if Path("/mnt/c").exists():
                scan_root = Path("/mnt/c/")
                console.print("[bold cyan]WSL detected: Scanning Windows C: drive via /mnt/c/[/]")
            else:
                scan_root = Path.home()
                console.print(f"[yellow]No directory specified. Scanning user home: {scan_root}[/]")
        
        console.print(f"[bold cyan]Default scan target: {scan_root}[/]")
        console.print("[yellow]Note: Full system scan may take a very long time. Press Ctrl+C to stop.[/]")

    if not scan_root.exists():
        console.print(f"[red]Error: Directory '{scan_root}' does not exist.[/]")
        sys.exit(1)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Initializing scan...", total=None)
        console.print("[dim]Counting files...[/]")
        file_count = sum(1 for _ in scan_root.rglob('*') if _.is_file())
        progress.update(task, total=file_count, description="[cyan]Scanning...")

        start_time = time.time()
        findings = scan_directory(scan_root, progress, task)

    display_summary(findings, start_time)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        sys.exit(0)