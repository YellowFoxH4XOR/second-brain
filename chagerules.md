+++
id = 'chage-rules'
title = 'Changelog Automation Rules'
scope = 'workspace'
target_audience = 'All Agents'
status = 'active'
+++

# Changelog Automation Rules

> This document defines how agents must read, modify, and maintain `changelog.md` for the project.

## 1. Read Current State
- **Locate** `changelog.md` at the repository root. If it does not exist, treat as new project and create it following the template in section 3.
- **Parse** the file to understand the latest project version, overview, and the most recent change entries.

## 2. Execute Task & Update Log
1. **Perform the Assigned Task** — implement code changes, documentation, configuration, etc.
2. **Immediately Append** a new bullet to the top of the change history in `changelog.md`:
   - Format: `- <ISO 8601 Timestamp>: <Concise description of the change> — <Files or components affected>`
   - Keep to **one line**; newest first.
3. **Update Version/Status** in the overview section if the change alters project version or major status.
4. **Save** the complete, updated `changelog.md`.

## 3. Template for New Changelog
If `changelog.md` is missing, initialize it with:
```markdown
# Project Name – Changelog
Intro paragraph summarising purpose, version, key components, status.

## Project Overview
- **Purpose**: ...
- **Current Version**: 0.1.0
- **Key Components**: ...
- **Overall Status**: Active development

## Change History (newest first)
- <ISO Timestamp>: Initial project scaffolding — created repository structure.
```

## 4. Editing & Deletions
- **Clarify or Correct**: Amend existing lines if they are inaccurate.
- **Delete Obsolete Entries**: If a change was reverted, remove its entry and add a new line noting the deletion.

## 5. Best Practices
- Use **UTC** timestamps.
- Remain factual and neutral; avoid subjective language.
- Be proactive: after any change, verify the changelog is current.

---

_Adhering to these rules ensures an accurate and trustworthy historical record._ 