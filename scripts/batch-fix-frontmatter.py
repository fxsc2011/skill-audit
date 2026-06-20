#!/usr/bin/env python3
"""
Batch fix: add missing `trigger` field to all SKILL.md files.
Safe — only appends to YAML frontmatter, leaves everything else untouched.
"""

import os, re, json, sys

SKILLS_DIR = os.path.expanduser("~/.hermes/skills")
DRY_RUN = '--dry-run' in sys.argv

def get_frontmatter(text):
    """Extract YAML frontmatter dict and its boundaries."""
    if not text.startswith('---'):
        return None, None, None
    end = text.find('---', 3)
    if end == -1:
        return None, None, None
    fm_text = text[3:end]
    
    # Parse key: value pairs (simple YAML, no nested)
    fm = {}
    current_key = None
    for line in fm_text.strip().split('\n'):
        m = re.match(r'^(\w[\w_-]*)\s*:\s*(.*)', line)
        if m:
            current_key = m.group(1)
            val = m.group(2).strip()
            # Strip quotes
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            elif val.startswith("'") and val.endswith("'"):
                val = val[1:-1]
            fm[current_key] = val
        elif current_key and line.startswith('  - '):
            # List item continuation
            item = line.strip()[3:].strip()
            if item.startswith('"') and item.endswith('"'):
                item = item[1:-1]
            existing = fm.get(current_key)
            if isinstance(existing, list):
                existing.append(item)
            elif existing:
                fm[current_key] = [existing, item]
            else:
                fm[current_key] = [item]
    
    return fm, 3, end


def generate_triggers(desc, name, skill_path=None):
    """Generate reasonable trigger lines from description and name."""
    triggers = []
    if isinstance(desc, list):
        desc = ' '.join(desc)
    if isinstance(name, list):
        name = name[0] if name else (os.path.basename(skill_path) if skill_path else name)
    desc_lower = desc.lower()
    
    # Pattern-based triggers
    if any(w in desc_lower for w in ['search', 'query', 'find', 'look up']):
        triggers.append(f"- 用户需要搜索或查询与 {name} 相关的信息")
    if any(w in desc_lower for w in ['create', 'write', 'generate', 'produce', 'build']):
        triggers.append(f"- 用户要求创建/生成内容（涉及 {name}）")
    if any(w in desc_lower for w in ['read', 'view', 'open', 'show', 'display']):
        triggers.append(f"- 用户要求查看/读取内容")
    if any(w in desc_lower for w in ['analyze', 'review', 'check', 'inspect', 'audit', 'scan', 'monitor']):
        triggers.append(f"- 用户需要对内容进行分析/检查")
    if any(w in desc_lower for w in ['send', 'message', 'email', 'post', 'tweet', 'imessage', 'sms']):
        triggers.append(f"- 用户要求发送消息/发布内容")
    if any(w in desc_lower for w in ['transcript', 'summary', 'summarize', 'briefing']):
        triggers.append(f"- 用户提供 URL 或要求总结/转录内容")
    if any(w in desc_lower for w in ['download', 'fetch', 'get data', 'crawl', 'scrape']):
        triggers.append(f"- 用户要求下载/获取数据")
    if any(w in desc_lower for w in ['convert', 'transform', 'translate', 'format']):
        triggers.append(f"- 用户要求格式转换或翻译")
    if any(w in desc_lower for w in ['install', 'setup', 'configure', 'deploy']):
        triggers.append(f"- 用户要求安装/配置/部署软件")
    if any(w in desc_lower for w in ['design', 'diagram', 'draw', 'image', 'art', 'video', 'animation', 'sketch']):
        triggers.append(f"- 用户要求生成视觉/多媒体内容")
    if any(w in desc_lower for w in ['play', 'music', 'song', 'audio', 'spotify']):
        triggers.append(f"- 用户要求播放/生成音乐或音频")
    if any(w in desc_lower for w in ['code', 'debug', 'programming', 'python', 'javascript', 'git', 'github', 'pr', 'pull request']):
        triggers.append(f"- 用户涉及编程/代码审查/GitHub 任务")
    if any(w in desc_lower for w in ['stock', 'stock data', 'finance', 'financial', 'k-line', 'market']):
        triggers.append(f"- 用户查询股票/金融/市场数据")
    if any(w in desc_lower for w in ['calendar', 'schedule', 'appointment', 'event', 'reminder']):
        triggers.append(f"- 用户要求管理日程/提醒事项")
    if any(w in desc_lower for w in ['note', 'obsidian', 'vault', 'documentation']):
        triggers.append(f"- 用户要求创建/读取/搜索笔记")
    if any(w in desc_lower for w in ['email', 'mail', 'inbox']):
        triggers.append(f"- 用户要求处理邮件")
    if any(w in desc_lower for w in ['mcp', 'model context protocol', 'tool server']):
        triggers.append(f"- 用户要求配置或使用 MCP 服务器/工具")
    if any(w in desc_lower for w in ['docker', 'container', 's6', 'supervision']):
        triggers.append(f"- 用户要求管理容器/服务")
    if any(w in desc_lower for w in ['lark', 'feishu', '飞书']):
        triggers.append(f"- 用户要求操作飞书（Lark）相关功能")
    if any(w in desc_lower for w in ['track', '追踪', '追踪', 'scan', 'screening']):
        triggers.append(f"- 用户要求追踪/扫描/筛选数据")
    if any(w in desc_lower for w in ['excel', 'spreadsheet', 'csv', 'sheet']):
        triggers.append(f"- 用户要求处理电子表格/数据文件")
    if any(w in desc_lower for w in ['pdf', 'document', 'ocr', 'scan']):
        triggers.append(f"- 用户要求处理文档/PDF/扫描件")
    if any(w in desc_lower for w in ['arxiv', 'paper', 'research', 'academic', 'journal']):
        triggers.append(f"- 用户要求查找/总结学术论文")
    if any(w in desc_lower for w in ['smart home', 'light', 'hue', 'philips']):
        triggers.append(f"- 用户要求控制智能家居设备")
    
    if not triggers:
        # Generic fallback
        triggers.append(f"- 用户提及与 {name} 相关的关键词")
        triggers.append(f"- 用户请求的功能涉及 {desc[:60]}...")
    
    return triggers


def fix_skill(skill_path, dry_run=True):
    """Add trigger to SKILL.md if missing. Returns (changed, reason)."""
    sk_md = os.path.join(skill_path, "SKILL.md")
    if not os.path.exists(sk_md):
        return False, "no SKILL.md"
    
    with open(sk_md, 'r') as f:
        text = f.read()
    
    fm, start, end = get_frontmatter(text)
    if fm is None:
        return False, "no frontmatter"
    
    if 'trigger' in fm:
        return False, "already has trigger"
    
    name = fm.get('name', os.path.basename(skill_path))
    desc = fm.get('description', '')
    
    triggers = generate_triggers(desc, name, skill_path)
    
    # Insert trigger after last field in frontmatter
    # Find the position just before the closing ---
    insert_pos = end
    trigger_text = "\ntrigger:\n" + "\n".join(triggers)
    
    new_text = text[:insert_pos] + trigger_text + text[insert_pos:]
    
    if not dry_run:
        with open(sk_md, 'w') as f:
            f.write(new_text)
    
    return True, f"added trigger with {len(triggers)} patterns"


# Main
stats = {"fixed": 0, "skipped": 0, "errors": 0, "details": []}

categories = sorted([d for d in os.listdir(SKILLS_DIR) 
                     if os.path.isdir(os.path.join(SKILLS_DIR, d)) and not d.startswith('.')])

for cat in categories:
    cat_path = os.path.join(SKILLS_DIR, cat)
    for skill in sorted(os.listdir(cat_path)):
        skill_path = os.path.join(cat_path, skill)
        if not os.path.isdir(skill_path):
            continue
        
        changed, reason = fix_skill(skill_path, dry_run=DRY_RUN)
        key = f"{cat}/{skill}"
        
        if changed:
            stats["fixed"] += 1
            stats["details"].append(f"  ✅ {key} — {reason}")
        elif reason == "already has trigger":
            stats["skipped"] += 1
        else:
            stats["skipped"] += 1
            if reason not in ("no SKILL.md", "no frontmatter"):
                stats["details"].append(f"  ⏭️ {key} — {reason}")

# Report
print(f"\n{'='*60}")
print(f"  {'[DRY RUN] ' if DRY_RUN else ''}Batch Frontmatter Fix")
print(f"{'='*60}")
print(f"  Skills scanned:  {stats['fixed'] + stats['skipped']}")
print(f"  ✅ Fixed:        {stats['fixed']}")
print(f"  ⏭️  Skipped:     {stats['skipped']}")
print(f"  ❌ Errors:       {stats['errors']}")
print()
if stats['details']:
    print("  Details:")
    for d in stats['details']:
        print(d)
print(f"{'='*60}")
print(f"\n  Run without --dry-run to apply fixes.")