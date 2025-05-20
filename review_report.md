# Secure Code Review Report

## Project Folder
internship

## Reviewed File
app.py

## Tool Used
- Bandit (Static Code Analyzer)

## Vulnerabilities Found
- SQL Injection (Line 9)

## Remediation
- Replaced string interpolation with parameterized query.
- Added `.strip()` on input to sanitize whitespace.

## Status
✅ Issue resolved
