# Example Outputs

This directory contains example outputs from the STIG generator to serve as style references for Cursor.

## Purpose

When refining generators, reference these examples to maintain consistent:
- Tone and language
- Structure and formatting
- Task organization
- Tag usage

## Files

- `rhel9/stig_rhel9_hardening_example.yml` - Example hardening playbook
- `rhel9/stig_rhel9_checker_example.yml` - Example checker playbook
- `rhel9/stig_rhel9_ctp_example.csv` - Example CTP document

## Usage with Cursor

When asking Cursor to refine generators, mention:

> "Use the style in examples/rhel9/stig_rhel9_ctp_example.csv as a reference for tone and structure, but improve clarity and remove awkward 'Must:' and 'If it does not, this is a finding.' language in the new generator."

This gives Cursor concrete, repo-local examples to pattern match.




