#!/usr/bin/env python3
"""
Skill Safety Audit — run before skill_manage(action='create') or periodically.

Usage:
    python3 /path/to/audit/skill <skill_dir_or_file>

Returns structured JSON report with pass/warn/block for each check.
"""

import os, sys, re, json, ast, pathlib, subprocess, tempfile, urllib.request, socket

# ── Configuration ──────────────────────────────────────────────────────────

DANGEROUS_PATTERNS = {
    "rm_root":       re.compile(r'(^|\s)(sudo\s+)?rm\s+(-rf?|--recursive)\s+/[\s;]'),
    "chmod_recursive": re.compile(r'(^|\s)(sudo\s+)?chmod\s+(-R|--recursive)\s+777\s'),
    "dd_destructive":  re.compile(r'(^|\s)(sudo\s+)?dd\s+if=/dev/zero\s+of='),
    "fork_bomb":       re.compile(r':\(\)\s*\{\s*:\|\|:\s*&\s*\}\s*;'),
}

PIPE_EXEC_PATTERNS = [
    re.compile(r'curl\s+.*\||wget\s+.*\||fetch\s+.*\|'),
    re.compile(r'\|\s*(bash|sh|zsh|python3?|perl|ruby|php)\s*$'),
    re.compile(r'\b(eval|exec)\s*\('),
]

# 安全的数据处理管道工具（pipe to these is NOT dangerous）
SAFE_PIPE_TARGETS = {'iconv', 'grep', 'egrep', 'fgrep', 'sed', 'awk', 'jq',
                     'tee', 'head', 'tail', 'sort', 'uniq', 'wc', 'cut',
                     'tr', 'xargs', 'cat', 'less', 'more', 'strings',
                     'base64', 'xxd', 'od', 'hexdump'}

SAFE_FILE_PATHS = [
    re.compile(r'^/tmp/'),
    re.compile(r'^~/.hermes/'),
    re.compile(r'^/Users/[^/]+/\.hermes/'),
    re.compile(r'^/opt/anaconda3/'),
    re.compile(r'^/usr/local/'),
]

IMPORT_WHITELIST = {
    # stdlib
    'os', 'sys', 'json', 're', 'math', 'time', 'datetime', 'random',
    'collections', 'pathlib', 'subprocess', 'tempfile', 'hashlib',
    'base64', 'csv', 'io', 'textwrap', 'functools', 'itertools',
    'typing', 'dataclasses', 'enum', 'copy', 'inspect',
    'ast', 'socket', 'pathlib', 'statistics', 'struct',
    '__future__', 'uuid', 'abc', 'dis', 'gc', 'pprint', 'atexit',
    'contextlib', 'weakref', 'operator', 'traceback', 'linecache',
    # network
    'urllib', 'urllib.request', 'urllib.parse', 'urllib.error',
    'http', 'http.client', 'ssl',
    # data
    'pandas', 'numpy', 'requests', 'akshare', 'xml', 'xml.etree', 'xml.etree.ElementTree',
    'openpyxl', 'xlrd', 'xlsxwriter', 'habanero', 'semanticscholar',
    # other common
    'pydantic', 'argparse', 'logging', 'warnings', 'shutil', 'glob',
    'decimal', 'fractions', 'string', 'zipfile',
    'tarfile', 'gzip', 'bz2', 'lzma',
    'platform', 'concurrent', 'torch', 'websocket', 'websocket-client',
    'PIL', 'Pillow', 'cv2', 'sklearn', 'scipy', 'matplotlib',
    'tqdm', 'colorama', 'rich', 'click', 'fire',
    'jinja2', 'yaml', 'toml', 'configparser',
    'numba', 'cupy', 'tensorboard', 'tabulate',
}

SUSPICIOUS_IMPORTS = {
    'socket': '网络连接',
    'ctypes': 'C 级内存访问',
    'multiprocessing': '进程创建',
    'threading': '线程',
    'signal': '信号处理',
    'fcntl': '文件控制',
    'telnetlib': 'Telnet 协议',
    'ftplib': 'FTP 协议',
    'smtplib': 'SMTP 邮件发送',
    'paramiko': 'SSH 连接',
    'cryptography': '加密库',
    'Crypto': 'PyCryptodome',
    'pexpect': '交互式进程控制',
}

REQUIRED_FRONTMATTER = ['name', 'description', 'trigger']


# ── Helpers ────────────────────────────────────────────────────────────────

def read_file_text(path):
    try:
        with open(os.path.expanduser(path), 'r', errors='replace') as f:
            content = f.read()
            return content
    except Exception as e:
        return None


# ── Checks ─────────────────────────────────────────────────────────────────

def _is_in_code_block(text, pos):
    """Check if position is inside a markdown fenced code block (```)."""
    before = text[:pos]
    fences = [m.start() for m in re.finditer(r'^```', before, re.MULTILINE)]
    return len(fences) % 2 == 1


def check_dangerous_commands(text, source_label):
    """Scan for destructive shell commands."""
    findings = []
    for name, pat in DANGEROUS_PATTERNS.items():
        for m in pat.finditer(text):
            line_no = text[:m.start()].count('\n') + 1
            findings.append({
                "severity": "block",
                "check": f"dangerous_command:{name}",
                "label": f"[{source_label}:{line_no}] 发现危险命令: `{m.group().strip()[:80]}`",
            })
    for pat in PIPE_EXEC_PATTERNS:
        for m in pat.finditer(text):
            line_no = text[:m.start()].count('\n') + 1
            # 跳过 markdown 代码块中的 curl 管道（都是文档示例）
            if _is_in_code_block(text, m.start()):
                continue
            # 检查 pipe 后是否是安全的数据处理工具
            after_pipe_raw = text[m.end():m.end()+30].strip() if m.group().endswith('|') else ''
            after_pipe = after_pipe_raw.split()[0] if after_pipe_raw else ''
            if after_pipe and after_pipe in SAFE_PIPE_TARGETS:
                continue
            if after_pipe.startswith('/'):
                continue  # 绝对路径 pipe 目标不判断（通常是系统工具）
            findings.append({
                "severity": "warn",
                "check": "pipe_exec",
                "label": f"[{source_label}:{line_no}] 管道/动态执行: `{m.group().strip()[:80]}`",
            })
    return findings


def check_frontmatter(text, source_label):
    """Check YAML frontmatter completeness."""
    findings = []
    if not text.startswith('---'):
        return [{"severity": "warn", "check": "frontmatter_missing",
                 "label": f"[{source_label}] 无 YAML frontmatter (不以 --- 开头)"}]
    
    # Extract frontmatter
    end = text.find('---', 3)
    if end == -1:
        return [{"severity": "block", "check": "frontmatter_broken",
                 "label": f"[{source_label}] YAML frontmatter 未正确闭合"}]
    
    fm = text[3:end]
    for field in REQUIRED_FRONTMATTER:
        pat = re.compile(rf'^{re.escape(field)}:\s*\S', re.MULTILINE)
        if not pat.search(fm):
            findings.append({
                "severity": "warn",
                "check": f"frontmatter_missing_field:{field}",
                "label": f"[{source_label}] 缺少必要 frontmatter 字段: `{field}`",
            })
    return findings


def check_scripts_python(path, source_label):
    """Static analysis of .py scripts."""
    findings = []
    if not path.endswith('.py'):
        return findings
    
    text = read_file_text(path)
    if text is None:
        findings.append({
            "severity": "warn",
            "check": "unreadable_file",
            "label": f"[{source_label}] 无法读取",
        })
        return findings
    
    # Syntax check
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        findings.append({
            "severity": "block",
            "check": "python_syntax_error",
            "label": f"[{source_label}] Python 语法错误: {e}",
        })
        return findings
    
    # Import analysis
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split('.')[0]
                if mod in SUSPICIOUS_IMPORTS:
                    findings.append({
                        "severity": "warn",
                        "check": f"suspicious_import:{mod}",
                        "label": f"[{source_label}] 可疑 import `{mod}` — {SUSPICIOUS_IMPORTS[mod]}",
                    })
                elif mod not in IMPORT_WHITELIST:
                    findings.append({
                        "severity": "warn",
                        "check": f"unknown_import:{mod}",
                        "label": f"[{source_label}] 非白名单 import `{mod}` — 人工确认",
                    })
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or '').split('.')[0]
            if mod in SUSPICIOUS_IMPORTS:
                findings.append({
                    "severity": "warn",
                    "check": f"suspicious_import:{mod}",
                    "label": f"[{source_label}] 可疑 import `{mod}` ({SUSPICIOUS_IMPORTS[mod]})",
                })
            elif mod and mod not in IMPORT_WHITELIST:
                findings.append({
                    "severity": "warn",
                    "check": f"unknown_import:{mod}",
                    "label": f"[{source_label}] 非白名单 import `{mod}` — 人工确认",
                })
    
    # os.system / subprocess without /tmp/ guard
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = _get_call_name(node)
            if func in ('os.system', 'subprocess.run', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_call'):
                findings.append({
                    "severity": "warn",
                    "check": "subprocess_call",
                    "label": f"[{source_label}:{node.lineno}] 调用了 `{func}` — 检查命令是否安全",
                })
            if func in ('os.remove', 'os.unlink', 'shutil.rmtree', 'os.rmdir'):
                findings.append({
                    "severity": "warn",
                    "check": "file_deletion",
                    "label": f"[{source_label}:{node.lineno}] 调用了 `{func}` — 检查删除路径是否安全",
                })
    
    # File operations — flag writes outside safe paths
    safe_prefixes = ('/tmp/', os.path.expanduser('~/.hermes/'), '/Users/', '/opt/anaconda3/', '/proc/', '/sys/')
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = _get_call_name(node)
            if func in ('open', 'os.open', 'pathlib.Path.write_text', 'pathlib.Path.write_bytes'):
                for child in ast.walk(node):
                    if isinstance(child, ast.Constant) and isinstance(child.value, str):
                        path = child.value
                        if path.startswith('/') and not path.startswith(safe_prefixes):
                            findings.append({
                                "severity": "warn",
                                "check": "file_outside_safe_paths",
                                "label": f"[{source_label}:{node.lineno}] 写文件到非常用路径: `{path[:80]}`",
                            })
    
    return findings


def _get_call_name(node):
    """Extract full call name like os.system from AST Call node."""
    if isinstance(node.func, ast.Attribute):
        parts = []
        n = node.func
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            parts.append(n.id)
        elif isinstance(n, ast.Call):
            return repr(n.func)[:30]
        return '.'.join(reversed(parts))
    elif isinstance(node.func, ast.Name):
        return node.func.id
    return repr(node.func)[:30]


def check_references_integrity(skill_dir, text, source_label):
    """Check that referenced files actually exist."""
    findings = []
    
    # Check references/ templates/ scripts/ subdirs
    for subdir in ['references', 'templates', 'scripts']:
        dir_path = os.path.join(skill_dir, subdir)
        if os.path.isdir(dir_path):
            files = os.listdir(dir_path)
            if not files:
                findings.append({
                    "severity": "warn",
                    "check": f"empty_dir:{subdir}",
                    "label": f"[{source_label}] `{subdir}/` 目录存在但为空",
                })
        elif re.search(rf'`{subdir}/', text):
            findings.append({
                "severity": "warn",
                "check": f"missing_dir:{subdir}",
                "label": f"[{source_label}] 正文引用了 `{subdir}/` 但实际目录不存在",
            })
    
    # Check script executability
    scripts_dir = os.path.join(skill_dir, 'scripts')
    if os.path.isdir(scripts_dir):
        for f in os.listdir(scripts_dir):
            fpath = os.path.join(scripts_dir, f)
            if f.endswith('.py'):
                try:
                    with open(fpath) as fh:
                        ast.parse(fh.read())
                except SyntaxError as e:
                    findings.append({
                        "severity": "block",
                        "check": "script_syntax_error",
                        "label": f"[{source_label}] scripts/{f} 语法错误: {e}",
                    })
            elif f.endswith('.sh'):
                # quick bash syntax check
                r = subprocess.run(['bash', '-n', fpath], capture_output=True, text=True, timeout=10)
                if r.returncode != 0:
                    findings.append({
                        "severity": "warn",
                        "check": "script_syntax_error",
                        "label": f"[{source_label}] scripts/{f} bash 语法问题: {r.stderr[:200]}",
                    })
    
    return findings


def check_skill_size(text, source_label):
    """Flag oversized skills."""
    lines = text.count('\n')
    if lines > 400:
        return [{"severity": "warn", "check": "skill_too_large",
                 "label": f"[{source_label}] skill 过长: {lines} 行 (>400)，建议精简"}]
    elif lines > 250:
        return [{"severity": "info", "check": "skill_large",
                 "label": f"[{source_label}] skill 较大: {lines} 行 (>250)，可考虑拆分"}]
    return []


# ── Main Audit ─────────────────────────────────────────────────────────────

def audit_skill(target_path):
    """Run full audit on a skill directory or file."""
    target = os.path.expanduser(target_path)
    report = {
        "target": target,
        "status": "pass",  # pass / warn / block
        "checks": [],
        "summary": {"pass": 0, "warn": 0, "block": 0, "info": 0},
    }
    
    if os.path.isdir(target):
        skill_md = os.path.join(target, 'SKILL.md')
        if not os.path.exists(skill_md):
            report["checks"].append({
                "severity": "block",
                "check": "missing_skill_md",
                "label": f"[{target}] 目录下没有 SKILL.md",
            })
            return report
        text = read_file_text(skill_md)
        if text is None:
            report["checks"].append({
                "severity": "block",
                "check": "unreadable_skill_md",
                "label": f"[{skill_md}] 无法读取: {text}",
            })
            return report
        
        # Run checks
        report["checks"].extend(check_frontmatter(text, 'SKILL.md'))
        report["checks"].extend(check_dangerous_commands(text, 'SKILL.md'))
        report["checks"].extend(check_skill_size(text, 'SKILL.md'))
        report["checks"].extend(check_references_integrity(target, text, 'SKILL.md'))
        
        # Check scripts
        scripts_dir = os.path.join(target, 'scripts')
        if os.path.isdir(scripts_dir):
            for f in os.listdir(scripts_dir):
                fpath = os.path.join(scripts_dir, f)
                ftext = read_file_text(fpath)
                if ftext is not None:
                    report["checks"].extend(check_dangerous_commands(ftext, f'scripts/{f}'))
                    report["checks"].extend(check_scripts_python(fpath, f'scripts/{f}'))
        
        # Check reference files for dangerous content too
        refs_dir = os.path.join(target, 'references')
        if os.path.isdir(refs_dir):
            for f in os.listdir(refs_dir):
                if f.endswith('.md'):
                    fpath = os.path.join(refs_dir, f)
                    ftext = read_file_text(fpath)
                    if ftext is not None:
                        report["checks"].extend(check_dangerous_commands(ftext, f'references/{f}'))
    
    elif os.path.isfile(target):
        text = read_file_text(target)
        if text is None:
            report["checks"].append({
                "severity": "block",
                "check": "unreadable_file",
                "label": f"[{target}] 无法读取: {text}",
            })
            return report
        report["checks"].extend(check_frontmatter(text, os.path.basename(target)))
        report["checks"].extend(check_dangerous_commands(text, os.path.basename(target)))
        report["checks"].extend(check_scripts_python(target, os.path.basename(target)))
    
    else:
        report["checks"].append({
            "severity": "block",
            "check": "not_found",
            "label": f"[{target}] 路径不存在",
        })
    
    # Summarize
    for c in report["checks"]:
        sev = c["severity"]
        report["summary"][sev] = report["summary"].get(sev, 0) + 1
    
    if report["summary"].get("block", 0) > 0:
        report["status"] = "block"
    elif report["summary"].get("warn", 0) > 0:
        report["status"] = "warn"
    
    return report


def print_report(report, verbose=True):
    """Pretty print audit report."""
    sev_icon = {"block": "❌", "warn": "⚠️", "pass": "✅", "info": "ℹ️"}
    
    print(f"\n{'='*60}")
    print(f"  Skill Audit Report")
    print(f"  Target: {report['target']}")
    print(f"  Status: {sev_icon.get(report['status'], '❓')} {report['status'].upper()}")
    print(f"{'='*60}")
    
    if not report["checks"]:
        print("\n  ✅ 未发现任何问题")
    elif verbose:
        by_sev = {"block": [], "warn": [], "info": [], "pass": []}
        for c in report["checks"]:
            by_sev.setdefault(c["severity"], []).append(c)
        
        for sev in ["block", "warn", "info"]:
            items = by_sev.get(sev, [])
            if items:
                print(f"\n  {'='*56}")
                print(f"  {sev_icon.get(sev, '?')} {sev.upper()} ({len(items)} 项)")
                print(f"  {'='*56}")
                for c in items:
                    print(f"    {c['label']}")
                    if verbose and 'detail' in c:
                        print(f"      {c['detail']}")
    
    s = report["summary"]
    print(f"\n  {'─'*56}")
    print(f"  总计: ❌ {s.get('block',0)} 拦截 | ⚠️ {s.get('warn',0)} 警告 | ℹ️ {s.get('info',0)} 信息 | ✅ 通过")
    print(f"{'='*60}\n")
    return report


# ── Fix frontmatter ────────────────────────────────────────────────────────

DEFAULT_FRONTMATTER = {
    'trigger': '  - user asks about this topic',
}

def fix_frontmatter(target_path):
    """Auto-add missing frontmatter fields to SKILL.md."""
    target = os.path.expanduser(target_path)
    skill_md = os.path.join(target, 'SKILL.md') if os.path.isdir(target) else target
    
    if not os.path.exists(skill_md):
        print(f"❌ 文件不存在: {skill_md}")
        return False
    
    with open(skill_md, 'r') as f:
        text = f.read()
    
    if not text.startswith('---'):
        print(f"❌ [{skill_md}] 无 YAML frontmatter，跳过修复")
        return False
    
    end = text.find('---', 3)
    if end == -1:
        print(f"❌ [{skill_md}] frontmatter 未闭合，跳过修复")
        return False
    
    fm = text[3:end]
    missing = []
    for field in REQUIRED_FRONTMATTER:
        pat = re.compile(rf'^{re.escape(field)}:\s*\S', re.MULTILINE)
        if not pat.search(fm):
            missing.append(field)
    
    if not missing:
        print(f"✅ [{skill_md}] 所有必要字段已存在")
        return True
    
    # Build insertion: add missing fields after the last existing field
    changes = []
    for field in missing:
        default = DEFAULT_FRONTMATTER.get(field, '  ') or '  '
        insert = f'{field}:\n{default}\n'
        changes.append(insert)
    
    # Insert at end of frontmatter (before the closing ---)
    insert_text = '\n' + ''.join(changes)
    new_text = text[:end] + insert_text + text[end:]
    
    with open(skill_md, 'w') as f:
        f.write(new_text)
    
    print(f"✅ [{skill_md}] 已添加缺失字段: {', '.join(missing)}")
    return True


# ── CLI entry ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 skill-audit.py <skill_dir_or_file> [--json] [--fix-frontmatter]")
        sys.exit(1)
    
    target = sys.argv[1]
    as_json = '--json' in sys.argv
    fix_fm = '--fix-frontmatter' in sys.argv
    
    if fix_fm:
        success = fix_frontmatter(target)
        sys.exit(0 if success else 1)
    
    report = audit_skill(target)
    
    if as_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report)
    
    sys.exit(0 if report['status'] == 'pass' else 1)
