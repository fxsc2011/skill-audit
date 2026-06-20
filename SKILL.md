---
name: skill-audit
description: "Skill 安全审计：在安装之前检查 SKILL.md 和 scripts/ 中是否存在恶意代码、危险命令、可疑 import、文件越界等风险"
trigger:
  - user 说 "审计 skill"、"检查 skill 安全"、"安装前扫描"、"全量审计"
  - 安装来自第三方/不明来源的 skill 之前
  - 批量检查所有已安装 skill 的健康状态
  - 批量修复缺失的 skill frontmatter 字段
---

# Skill Safety Audit

在 `skill_manage(action='create')` 之前手动跑一遍，或在批量检查时扫描所有已安装 skill。

## 使用方式

### 审计单个 skill

```bash
python3 ~/.hermes/skills/devops/skill-audit/scripts/audit.py ~/.hermes/skills/<category>/<skill-name>/
```

### 全量审计

```bash
for d in ~/.hermes/skills/*/*/; do
  python3 ~/.hermes/skills/devops/skill-audit/scripts/audit.py "$d"
done
```

或使用 analyze_skills.py 汇总统计：
```bash
python3 ~/.hermes/skills/devops/skill-audit/scripts/analyze-skills.py
```

### JSON 输出（程序化处理）

```bash
python3 ~/.hermes/skills/devops/skill-audit/scripts/audit.py ~/.hermes/skills/<path>/ --json
```

### 批量修复缺失 frontmatter 字段

一键补齐所有 SKILL.md 的 `trigger` 字段：

```bash
python3 ~/.hermes/skills/devops/skill-audit/scripts/batch-fix-frontmatter.py
```

先 dry-run 看改什么：
```bash
python3 ~/.hermes/skills/devops/skill-audit/scripts/batch-fix-frontmatter.py --dry-run
```

会根据每个 skill 的 `description` 关键词自动生成合理的 trigger（search→搜索, create→创建, analyze→分析, send→发送等），不匹配的用通用回退。如果生成的 trigger 不够准，手动编辑 SKILL.md 修正。

**实战结果（2026-06-20）：** 全量扫描 127 个 skill，88 个缺 `trigger` 字段。`batch-fix-frontmatter.py` 自动修复后，PASS 数从 12→65，WARN 从 84→29。

## 审计内容

### 🔴 拦截级 (block)
| 检查 | 说明 |
|------|------|
| `dangerous_command` | `rm -rf /`、`dd if=/dev/zero`、fork bomb 等破坏性命令 |
| `python_syntax_error` | 脚本语法错误 → 无法运行 |
| `missing_skill_md` | 目录下没有 SKILL.md |
| `script_syntax_error` | scripts/ 下的 .py/.sh 有语法问题 |

### 🟡 警告级 (warn)
| 检查 | 说明 |
|------|------|
| `pipe_exec` | curl/wget|bash/sh 管道执行（排除 iconv/grep/jq 等安全管道，并跳过 markdown 代码块中的文档示例） |
| `subprocess_call` | os.system / subprocess.run（需人工确认命令安全） |
| `file_deletion` | os.remove / shutil.rmtree（需确认删除路径） |
| `suspicious_import` | socket/ctypes/multiprocessing/paramiko 等 |
| `unknown_import` | 非白名单包名 — 人工确认 |
| `file_outside_safe_paths` | 写文件到 /tmp/ ~/.hermes/ /proc/ 等之外（/proc/ /sys/ 已被标记为安全只读路径） |
| `frontmatter_missing` | 缺少 YAML frontmatter 或必要字段（常见 — 用 batch-fix-frontmatter.py 自动修复） |
| `skill_too_large` | >400 行建议精简 |

### 🟢 信息级 (info)
| 检查 | 说明 |
|------|------|
| `skill_large` | >250 行，可考虑拆分 |
| `empty_dir` | references/ 等子目录存在但为空 |

## 工作流

1. 下载/收到 skill → **先审计**
2. `python3 audit.py <skill_dir>` → 看报告
3. ❌ block → 拒绝安装 / 修完再装
4. ⚠️ warn → 逐条确认，无法解释的拒绝
5. ✅ pass → 安全，可以 `skill_manage(action='create')`

## 安全白名单维护

审计脚本的 IMPORT_WHITELIST 在 `audit.py` 顶部。遇到合法但未登记的 import 时：

```python
# 加到 IMPORT_WHITELIST（约第 42 行）
'package_name',  # 简短注释说明用途
```

如果 import 属于 `_common`、`run_workflow` 等本地模块（同一 skill 下的兄弟文件），不需要加白名单 — 这些跨文件引用是正常的项目结构。

## 技能体积精简模式

当 audit 报 `skill_too_large` 时，标准修复流程：

1. 识别非核心内容：扩展 API 端点表、完整案例研究、重复的陷阱列表、完整代码块
2. 移到 `references/` 下
3. SKILL.md 正文只留核心指令 + 一行指向参考文件的链接
4. 目标：200-300 行以内

**实战案例：**
- `a-share-stock-data`: 567→305 行（Section 9 全量 API 端点表移入 `references/extended-api-endpoints.md`）
- `daily-financial-briefing`: 342→100 行（重复陷阱列表 + 完整代码块压缩为指令式提示）

## 已知局限

- **无法检测逻辑层后门**（如"在特定日期执行特定操作"）— 仍需人工审查
- `unknown_import` 对本地模块（`_common` 等）的误报是设计使然 — 这些确实是未知模块，需要人工确认
- 内置 `pipe_exec` 检测会跳过 markdown 代码块，但不会跳过 `.sh` 脚本 — 后者中的 `curl | python3` 是真要执行的
