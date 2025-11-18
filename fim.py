import configparser
import sys
from pathlib import Path
import hashlib
import sqlite3
import argparse
import os

# --- The Hashing Engine (No changes) ---
def get_file_hash(file_path):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except PermissionError:
        return "PERMISSION_DENIED"
    except FileNotFoundError:
        return "FILE_NOT_FOUND"
    except Exception as e:
        return f"ERROR: {e}"

# --- The Database Setup (No changes) ---
def init_database(db_path):
    """Creates the baseline.db file and a 'files' table."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            hash TEXT
        )
        ''')
        cursor.execute("DELETE FROM files")
        conn.commit()
        print(f"Database '{db_path}' initialized.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()

# --- NEW FUNCTION: Load Baseline into Memory ---
def load_baseline(db_path):
    """Loads the baseline from the database into a dictionary for fast lookups."""
    baseline = {}
    if not os.path.exists(db_path):
        print(f"Error: Baseline database '{db_path}' not found.")
        print("Please run --init first.")
        sys.exit(1)
        
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Select all records from the 'files' table
        cursor.execute("SELECT path, hash FROM files")
        records = cursor.fetchall()
        
        # Store in a dictionary: {'filepath': 'hash'}
        for record in records:
            baseline[record[0]] = record[1]
            
        print(f"Loaded {len(baseline)} files from the baseline.")
        return baseline
        
    except sqlite3.Error as e:
        print(f"Database error loading baseline: {e}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()

# --- This is the main "entry point" of your script ---
def main():
    
    # --- UPDATED: Add --scan to the "Menu" ---
    parser = argparse.ArgumentParser(description="A simple File Integrity Monitor.")
    parser.add_argument(
        '--init', 
        action='store_true', 
        help="Initialize the baseline database. Deletes all existing data."
    )
    # ADD THIS NEW ARGUMENT
    parser.add_argument(
        '--scan', 
        action='store_true', 
        help="Scan files against the baseline."
    )
    
    args = parser.parse_args()
    
    # --- 1. Read Config File (No changes) ---
    config = configparser.ConfigParser()
    try:
        config.read('config.ini')
    except FileNotFoundError:
        print("ERROR: config.ini file not found. Exiting.")
        sys.exit(1)

    try:
        dir_to_watch_str = config.get('MonitorSettings', 'directory_to_watch')
        ignore_extensions_str = config.get('MonitorSettings', 'file_extensions_to_ignore')
        extensions_to_ignore = [ext.strip() for ext in ignore_extensions_str.split(',')]
    except (configparser.NoOptionError, configparser.NoSectionError) as e:
        print(f"ERROR: Problem with config.ini - {e}")
        sys.exit(1)

    # Database file name
    db_file = "baseline.db"

    # --- Logic for --init mode (No changes) ---
    if args.init:
        print("--- Initializing Baseline ---")
        
        init_database(db_file)
        
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            directory_path = Path(dir_to_watch_str)
            if not directory_path.exists():
                print(f"ERROR: Directory not found: {directory_path}")
                sys.exit(1)
            
            print(f"Scanning {directory_path} to build baseline...")
            
            for file_path in directory_path.rglob('*'):
                if file_path.is_file():
                    if file_path.suffix not in extensions_to_ignore:
                        current_hash = get_file_hash(file_path)
                        if "ERROR" not in current_hash:
                            print(f"  Adding: {file_path.name}")
                            cursor.execute(
                                "INSERT INTO files (path, hash) VALUES (?, ?)",
                                (str(file_path), current_hash)
                            )
                        else:
                            print(f"  (Skipping {file_path.name}: {current_hash})")
            
            conn.commit()
            print("--- Baseline creation complete! ---")

        except sqlite3.Error as e:
            print(f"Database error during baseline creation: {e}")
        finally:
            if conn:
                conn.close()
    
    # --- NEW: Logic for --scan mode ---
    elif args.scan:
        print("--- Scanning System Against Baseline ---")
        
        # 1. Load the "golden record" into memory
        baseline = load_baseline(db_file)
        # Create a copy to track what we've seen
        baseline_check = baseline.copy()

        # 2. Walk the file system just like in --init
        directory_path = Path(dir_to_watch_str)
        if not directory_path.exists():
            print(f"ERROR: Directory not found: {directory_path}")
            sys.exit(1)
        
        for file_path in directory_path.rglob('*'):
            if file_path.is_file():
                if file_path.suffix not in extensions_to_ignore:
                    
                    # Convert file_path to string for dictionary lookup
                    path_str = str(file_path)
                    
                    # 3. Calculate the file's CURRENT hash
                    current_hash = get_file_hash(file_path)
                    
                    if "ERROR" in current_hash:
                        print(f"  (Skipping {file_path.name}: {current_hash})")
                        continue # Skip to the next file

                    # 4. Compare with the baseline
                    if path_str in baseline:
                        # Case 1: File is in the baseline
                        if current_hash == baseline[path_str]:
                            # Hashes match - file is OK
                            pass # We'll just ignore it
                        else:
                            # Hashes DON'T match - file was MODIFIED
                            print(f"[MODIFIED] {path_str}")
                        
                        # We've seen this file, so remove it from our check list
                        if path_str in baseline_check:
                            del baseline_check[path_str]
                            
                    else:
                        # Case 2: File is NOT in baseline - it's NEW
                        print(f"[NEW] {path_str}")

        # 5. Check for DELETED files
        # After the loop, any file *still* in baseline_check was NOT
        # found during the scan, which means it was DELETED.
        for path_str in baseline_check:
            print(f"[DELETED] {path_str}")
            
        print("--- Scan complete ---")
    
    else:
        # If no argument is given, print the help menu
        print("No action specified. Use --init or --scan.")
        parser.print_help()

# --- This line makes the script run the main() function ---
if __name__ == "__main__":
    main()