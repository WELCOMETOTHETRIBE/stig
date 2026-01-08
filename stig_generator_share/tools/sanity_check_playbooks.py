#!/usr/bin/env python3
"""
Sanity checker for generated STIG hardening playbooks.

Run this from the repo root with:
    python tools/sanity_check_playbooks.py

If any check fails, it exits non-zero.
"""

import sys
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml  # PyYAML
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    print("WARNING: PyYAML is not installed. YAML parsing validation will be skipped.", file=sys.stderr)
    print("         Install with: pip install pyyaml (or pip install --user pyyaml)", file=sys.stderr)
    print("         Continuing with other checks...", file=sys.stderr)


# --------------------------------------------------------------------
# Configuration: update paths if your playbooks live elsewhere
# --------------------------------------------------------------------

# Paths relative to repo root (stig_generator/)
PLAYBOOKS = {
    "rhel8": Path("output/ansible/stig_rhel8_hardening.yml"),
    "rhel9": Path("output/ansible/stig_rhel9_hardening.yml"),
    "windows11": Path("output/ansible/stig_windows11_hardening.yml"),
    "windows2022": Path("output/ansible/stig_windows2022_hardening.yml"),
}

OS_META = {
    "rhel8": {
        "display_name": "RHEL 8",
        "expected_play_name": "RHEL 8 STIG Hardening",
        "expected_os_family": "RedHat",
        "expected_version_string": "8",
        "os_tag": "rhel8",
        "is_windows": False,
    },
    "rhel9": {
        "display_name": "RHEL 9",
        "expected_play_name": "RHEL 9 STIG Hardening",
        "expected_os_family": "RedHat",
        "expected_version_string": "9",
        "os_tag": "rhel9",
        "is_windows": False,
    },
    "windows11": {
        "display_name": "Windows 11",
        "expected_play_name": "Windows 11 STIG Hardening",
        "expected_os_family": "Windows",
        # we only enforce family for now; version/name checks could be added later
        "expected_version_string": None,
        "os_tag": "windows11",
        "is_windows": True,
    },
    "windows2022": {
        "display_name": "Windows Server 2022",
        "expected_play_name": "Windows Server 2022 STIG Hardening",
        "expected_os_family": "Windows",
        "expected_version_string": None,
        "os_tag": "windows2022",
        "is_windows": True,
    },
}


# Keys that are NOT ansible modules
NON_MODULE_KEYS = {
    "name",
    "tags",
    "when",
    "vars",
    "register",
    "changed_when",
    "failed_when",
    "notify",
    "loop",
    "loop_control",
    "with_items",
    "become",
    "delegate_to",
    "ignore_errors",
    "environment",
    "block",
    "rescue",
    "always",
}


def load_playbook(path: Path) -> List[Dict[str, Any]]:
    if not HAS_YAML:
        # Fallback: use basic text parsing for critical checks
        # This is less robust but allows validation without PyYAML
        return None  # Signal to use text-based validation
    
    try:
        with path.open("r", encoding="utf-8") as f:
            data = list(yaml.safe_load_all(f))
    except Exception as e:
        raise RuntimeError(f"YAML load failed for {path}: {e}")

    if not data:
        raise RuntimeError(f"{path} is empty or did not contain any YAML documents")

    if not isinstance(data[0], list):
        raise RuntimeError(f"{path} top-level YAML must be a list of plays")

    return data[0]


def find_module_name(task: Dict[str, Any]) -> str:
    """
    Try to guess the Ansible module name for a task by looking for the first key
    that is not obviously a control/meta key.
    """
    for key in task.keys():
        if key not in NON_MODULE_KEYS:
            return key
    return ""


def iter_tasks(play: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Return a flat list of tasks in the play (ignores roles/imports/blocks for now).
    """
    tasks = play.get("tasks", []) or []
    # You can extend this to look into 'block', 'rescue', etc., if your generator uses them.
    return tasks


def check_play_header_text(playbook_key: str, content: str, errors: List[str]) -> None:
    """Text-based play header check (fallback when PyYAML not available)."""
    meta = OS_META[playbook_key]
    expected_name = meta["expected_play_name"]
    expected_family = meta["expected_os_family"]
    expected_version = meta["expected_version_string"]
    
    # Check play name
    if f'name: "{expected_name}"' not in content and f"name: '{expected_name}'" not in content:
        # Try to find what name is actually there
        import re
        name_match = re.search(r'- name:\s*["\']?([^"\'\n]+)', content)
        if name_match:
            actual_name = name_match.group(1)
            errors.append(
                f"[{playbook_key}] Play name mismatch: expected '{expected_name}', got '{actual_name}'"
            )
        else:
            errors.append(f"[{playbook_key}] Could not find play name in file")
    
    # Check OS family assertion
    need_family = f"os_family'] == '{expected_family}'"
    if need_family not in content:
        errors.append(
            f"[{playbook_key}] OS verification missing family check; expected:\n"
            f"    ansible_facts['{need_family}"
        )
    
    # Check version assertion for RHEL
    if not meta["is_windows"] and expected_version:
        need_version = f"distribution_major_version'] == '{expected_version}'"
        if need_version not in content:
            errors.append(
                f"[{playbook_key}] OS verification missing version check; expected:\n"
                f"    ansible_facts['{need_version}"
            )


def check_play_header(playbook_key: str, play: Dict[str, Any], errors: List[str]) -> None:
    meta = OS_META[playbook_key]
    expected_name = meta["expected_play_name"]
    expected_family = meta["expected_os_family"]
    expected_version = meta["expected_version_string"]

    actual_name = play.get("name")
    if actual_name != expected_name:
        errors.append(
            f"[{playbook_key}] Play name mismatch: expected '{expected_name}', got '{actual_name}'"
        )

    pre_tasks = play.get("pre_tasks", []) or []
    assert_tasks = [
        t for t in pre_tasks
        if isinstance(t, dict) and ("ansible.builtin.assert" in t or "assert" in t)
    ]
    if not assert_tasks:
        errors.append(f"[{playbook_key}] No ansible.builtin.assert pre_task found for OS verification")
        return

    # Check the first assert task
    assert_task = assert_tasks[0]
    assert_body = assert_task.get("ansible.builtin.assert") or assert_task.get("assert") or {}
    that_list = assert_body.get("that") or []

    if not isinstance(that_list, list) or not that_list:
        errors.append(f"[{playbook_key}] OS verification assert has no 'that' list")
        return

    that_strs = [str(x) for x in that_list]

    # Check family
    need_family = f"ansible_facts['os_family'] == '{expected_family}'"
    if need_family not in that_strs:
        errors.append(
            f"[{playbook_key}] OS verification missing family check; expected condition:\n"
            f"    {need_family}\n"
            f"Got:\n"
            + "\n".join(f"    {s}" for s in that_strs)
        )

    # For Windows we currently only enforce family. For RHEL we also enforce major version.
    if not meta["is_windows"] and expected_version:
        need_version = f"ansible_facts['distribution_major_version'] == '{expected_version}'"
        if need_version not in that_strs:
            errors.append(
                f"[{playbook_key}] OS verification missing version check; expected condition:\n"
                f"    {need_version}\n"
                f"Got:\n"
                + "\n".join(f"    {s}" for s in that_strs)
            )


def check_tags_and_modules_text(playbook_key: str, content: str, errors: List[str]) -> None:
    """Text-based tag and module check (fallback when PyYAML not available)."""
    meta = OS_META[playbook_key]
    os_tag = meta["os_tag"]
    is_windows = meta["is_windows"]
    
    import re
    
    # Find all task blocks - improved pattern to handle multiline names and comments
    # Look for STIG ID comments followed by tasks
    task_pattern = r'# STIG ID: ([^\n]+)\n.*?(- name:\s*["\']([^"\']+)["\'])\s*\n(.*?)(?=\n\s*# STIG ID:|\Z)'
    tasks = re.finditer(task_pattern, content, re.DOTALL)
    
    for task_match in tasks:
        stig_id = task_match.group(1)
        task_name_line = task_match.group(2)
        task_name = task_match.group(3)
        task_content = task_match.group(4)
        
        # Check OS tag - look for it in the task content
        if f'- {os_tag}' not in task_content and f' {os_tag}' not in task_content:
            # Extract tags to show what's there
            tag_match = re.search(r'tags:\s*\n((?:\s+- [^\n]+\n?)+)', task_content)
            if tag_match:
                tags_str = tag_match.group(1)
                errors.append(
                    f"[{playbook_key}] Task '{task_name[:60]}...' missing OS tag '{os_tag}'\n"
                    f"    STIG ID: {stig_id}\n"
                    f"    Tags found: {tags_str[:200]}"
                )
            else:
                # Task has no tags section at all
                errors.append(
                    f"[{playbook_key}] Task '{task_name[:60]}...' has no tags section\n"
                    f"    STIG ID: {stig_id}"
                )
        
        # Check automation tags and modules
        has_automated = 'automation_automated' in task_content
        has_manual_only = 'automation_manual_only' in task_content
        
        if has_automated and has_manual_only:
            errors.append(
                f"[{playbook_key}] Task '{task_name[:60]}...' has both automation_automated and automation_manual_only"
            )
        
        # Check module usage
        if has_automated:
            # Check if it's debug-only
            if 'ansible.builtin.debug:' in task_content or 'debug:' in task_content:
                errors.append(
                    f"[{playbook_key}] Task '{task_name[:60]}...' is automation_automated but uses debug module"
                )
            
            # For Windows, check for Windows modules
            if is_windows:
                if 'ansible.windows.' not in task_content and 'community.windows.' not in task_content:
                    errors.append(
                        f"[{playbook_key}] Windows task '{task_name[:60]}...' is automation_automated "
                        f"but does not use Windows modules"
                    )
        
        if has_manual_only:
            # Should be debug-only
            if 'ansible.builtin.debug:' not in task_content and 'debug:' not in task_content:
                # Check for real modules
                module_pattern = r'(ansible\.(?:builtin|windows)\.\w+|community\.windows\.\w+):'
                if re.search(module_pattern, task_content):
                    errors.append(
                        f"[{playbook_key}] Task '{task_name[:60]}...' is automation_manual_only "
                        f"but uses non-debug module"
                    )


def check_tags_and_modules(playbook_key: str, play: Dict[str, Any], errors: List[str]) -> None:
    meta = OS_META[playbook_key]
    os_tag = meta["os_tag"]
    is_windows = meta["is_windows"]

    tasks = iter_tasks(play)
    if not tasks:
        errors.append(f"[{playbook_key}] No tasks found in play")
        return

    for idx, task in enumerate(tasks, start=1):
        if not isinstance(task, dict):
            errors.append(f"[{playbook_key}] Task #{idx} is not a dict: {task}")
            continue

        name = task.get("name", f"(unnamed task #{idx})")
        tags = task.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        # Ignore non-STIG support tasks
        if "stig" not in tags:
            continue

        # 1) OS tag presence & exclusivity
        if os_tag not in tags:
            errors.append(
                f"[{playbook_key}] Task '{name}' missing OS tag '{os_tag}' "
                f"(tags: {tags})"
            )

        # 2) Automation vs module sanity
        module_name = find_module_name(task)
        has_automated = "automation_automated" in tags
        has_manual_only = "automation_manual_only" in tags

        if has_automated and has_manual_only:
            errors.append(
                f"[{playbook_key}] Task '{name}' has both automation_automated and "
                f"automation_manual_only tags"
            )

        # Automated tasks must not be debug-only
        if has_automated:
            if module_name in ("ansible.builtin.debug", "debug", ""):
                errors.append(
                    f"[{playbook_key}] Task '{name}' is tagged automation_automated "
                    f"but uses debug-only module '{module_name}'"
                )

            if is_windows:
                # For Windows, automated tasks must use ansible.windows.* or community.windows.*
                if not (
                    module_name.startswith("ansible.windows.")
                    or module_name.startswith("community.windows.")
                ):
                    errors.append(
                        f"[{playbook_key}] Windows task '{name}' is automation_automated "
                        f"but module '{module_name}' is not a Windows module"
                    )

        # Manual-only tasks must be debug-only (no real config changes)
        if has_manual_only:
            if module_name not in ("ansible.builtin.debug", "debug", ""):
                errors.append(
                    f"[{playbook_key}] Task '{name}' is automation_manual_only "
                    f"but uses non-debug module '{module_name}'"
                )


def check_ansible_syntax(path: Path) -> tuple[bool, str]:
    """
    Run ansible-playbook --syntax-check on the playbook.
    Returns (success, error_message).
    """
    import subprocess
    
    try:
        result = subprocess.run(
            ["ansible-playbook", "--syntax-check", str(path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, ""
        else:
            error_msg = result.stderr or result.stdout or "Unknown error"
            return False, error_msg[:500]  # Limit error message length
    except FileNotFoundError:
        return True, "ansible-playbook not found, skipping syntax check"
    except subprocess.TimeoutExpired:
        return False, "ansible-playbook --syntax-check timed out"
    except Exception as e:
        return False, f"Error running ansible-playbook: {e}"


def run_checks() -> int:
    all_errors: List[str] = []

    for key, path in PLAYBOOKS.items():
        meta = OS_META[key]
        display = meta["display_name"]

        if not path.exists():
            all_errors.append(f"[{key}] Playbook file not found: {path}")
            continue

        print(f"Checking {display} playbook: {path}")
        
        # Load playbook content
        try:
            with path.open("r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            all_errors.append(f"[{key}] Error reading file: {e}")
            continue
        
        # First check: YAML validity and structure (if PyYAML available)
        plays = load_playbook(path)
        
        if plays is None:
            # PyYAML not available, use text-based checks
            print(f"  Using text-based validation (PyYAML not available)")
            check_play_header_text(key, content, all_errors)
            check_tags_and_modules_text(key, content, all_errors)
        else:
            # PyYAML available, use structured checks
            if not plays:
                all_errors.append(f"[{key}] No plays found in {path}")
                continue

            play = plays[0]

            # Second check: Play header and OS assertions
            check_play_header(key, play, all_errors)
            
            # Third check: Tags and modules
            check_tags_and_modules(key, play, all_errors)
        
        # Fourth check: Ansible syntax check
        print(f"  Running ansible-playbook --syntax-check...")
        syntax_ok, syntax_error = check_ansible_syntax(path)
        if not syntax_ok:
            if "ansible-playbook not found" in syntax_error:
                print(f"  ⚠️  {syntax_error}")
            else:
                all_errors.append(
                    f"[{key}] ansible-playbook --syntax-check failed:\n"
                    f"    {syntax_error}"
                )
        else:
            print(f"  ✅ ansible-playbook --syntax-check passed")

    if all_errors:
        print("\n=== SANITY CHECK FAILED ===")
        for err in all_errors:
            print("- " + err)
        return 1

    print("\n=== SANITY CHECK PASSED ===")
    return 0


if __name__ == "__main__":
    sys.exit(run_checks())

