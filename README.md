# python-file-integrity-monitor


This is a MVP of File Integrity Monitor
Python File Integrity Monitor (FIM)
A lightweight, GUI-based File Integrity Monitor built with Python and Tkinter. This tool allows users to manually select files or directories to monitor, creating a secure baseline of SHA-256 hashes. Users can run on-demand scans to detect if files have been modified or deleted since the baseline was established.

Key Features

Hash-Based Integrity: Uses the SHA-256 hashing algorithm to detect even the slightest changes in file content.

GUI Interface: User-friendly Tkinter interface for managing files without needing the command line.

Recursive Directory Scanning: Ability to add entire folders; the script automatically walks through subdirectories to add all containing files.

Persistent Baseline: Uses a local SQLite database (baseline.db) to store file records, allowing the baseline to persist even after the application is closed.

Tech Stack

Language: Python 3
GUI: Tkinter (ttk)
Database: SQLite3
Security: hashlib (SHA-256)
