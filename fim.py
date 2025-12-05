import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import sqlite3
import os
from pathlib import Path

# --- CORE LOGIC (Functions omitted for brevity, assume they are correct) ---

def calculate_file_hash(filepath):
    """Calculates SHA-256 hash."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        return "ERROR"

def init_db():
    """Ensures the DB exists."""
    conn = sqlite3.connect("baseline.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            hash TEXT
        )
    ''')
    conn.commit()
    conn.close()

# --- THE GUI APPLICATION CLASS ---

class FIMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python File Integrity Monitor")
        self.root.geometry("900x600")

        # Initialize Database
        init_db()

        # --- 1. Top Control Panel (Adding files/folders) ---
        control_frame = ttk.LabelFrame(root, text="Configuration")
        control_frame.pack(fill="x", padx=10, pady=5)

        btn_add_folder = ttk.Button(control_frame, text="Add Folder", command=self.add_folder)
        btn_add_folder.pack(side="left", padx=5, pady=5)

        btn_add_file = ttk.Button(control_frame, text="Add Single File", command=self.add_file)
        btn_add_file.pack(side="left", padx=5, pady=5)

        btn_remove = ttk.Button(control_frame, text="Remove Selected", command=self.remove_selected)
        btn_remove.pack(side="left", padx=5, pady=5)

        btn_clear = ttk.Button(control_frame, text="Clear List", command=self.clear_list)
        btn_clear.pack(side="right", padx=5, pady=5)

        # --- 2. Main Display Area (The Treeview) ---
        self.tree = ttk.Treeview(root, columns=("Path", "Status", "Hash"), show="headings")
        
        # Define Column Headings
        self.tree.heading("Path", text="File Path")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Hash", text="SHA-256 Hash")

        # Define Column Widths
        self.tree.column("Path", width=500)
        self.tree.column("Status", width=100)
        self.tree.column("Hash", width=250)

        # Add a Scrollbar
        scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        # Define Colors for Status tags
        self.tree.tag_configure("modified", foreground="red", background="#ffe6e6") # Light red bg
        self.tree.tag_configure("new", foreground="green", background="#e6ffe6")    # Light green bg
        self.tree.tag_configure("deleted", foreground="gray")
        self.tree.tag_configure("error", foreground="orange")
        self.tree.tag_configure("ok", foreground="black")

        # --- 3. Bottom Action Panel (Baseline & Scan) ---
        action_frame = ttk.Frame(root)
        action_frame.pack(fill="x", padx=10, pady=10)

        btn_baseline = ttk.Button(action_frame, text="Update Baseline (Commit Changes)", command=self.update_baseline)
        btn_baseline.pack(side="left", fill="x", expand=True, padx=5)

        btn_scan = ttk.Button(action_frame, text="Scan Now (Check Integrity)", command=self.scan_files)
        btn_scan.pack(side="left", fill="x", expand=True, padx=5)

        # Load existing data if available
        self.load_from_db_to_ui()

    # --- INTERFACE FUNCTIONS ---

    def add_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            # Walk the folder and add all files
            count = 0
            for root_dir, dirs, files in os.walk(folder_selected):
                for file in files:
                    full_path = os.path.join(root_dir, file)
                    # Avoid duplicates
                    if not self.is_in_tree(full_path):
                        self.tree.insert("", "end", values=(full_path, "Pending", ""))
                        count += 1
            messagebox.showinfo("Success", f"Added {count} files from folder.")

    def add_file(self):
        files_selected = filedialog.askopenfilenames()
        if files_selected:
            for file in files_selected:
                if not self.is_in_tree(file):
                    self.tree.insert("", "end", values=(file, "Pending", ""))

    def remove_selected(self):
        """Removes selected files from the UI AND deletes them from the database."""
        selected_items = self.tree.selection()
        
        if not selected_items:
            messagebox.showwarning("Warning", "No files selected.")
            return

        conn = sqlite3.connect("baseline.db")
        cursor = conn.cursor()
        
        for item in selected_items:
            # 1. Get the file path from the selected row (Value in the 'Path' column)
            filepath = self.tree.item(item)['values'][0]
            
            # 2. Delete the record from the database
            cursor.execute("DELETE FROM files WHERE path=?", (filepath,))
            
            # 3. Delete the row from the UI Treeview
            self.tree.delete(item)
            
        conn.commit()
        conn.close()
        messagebox.showinfo("Removed", f"Removed {len(selected_items)} files from the monitoring list and database.")

    def clear_list(self):
        """Clears the entire UI list and completely wipes the database."""
        if messagebox.askyesno("Confirm", "⚠️ WARNING: Clear ALL files from monitor and wipe the baseline database?"):
            
            # 1. Clear the entire database table
            conn = sqlite3.connect("baseline.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM files")
            conn.commit()
            conn.close()
            
            # 2. Clear the UI
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            messagebox.showinfo("Cleared", "Monitoring list and baseline database have been wiped.")


    def is_in_tree(self, filepath):
        """Helper to check if file is already in the list."""
        for item in self.tree.get_children():
            if self.tree.item(item)['values'][0] == filepath:
                return True
        return False

    def load_from_db_to_ui(self):
        """Loads the database content into the UI on startup."""
        conn = sqlite3.connect("baseline.db")
        cursor = conn.cursor()
        cursor.execute("SELECT path, hash FROM files")
        rows = cursor.fetchall()
        for row in rows:
            # Insert with 'OK' status initially
            self.tree.insert("", "end", values=(row[0], "Monitored", row[1]), tags=("ok",))
        conn.close()

    # --- LOGIC FUNCTIONS ---

    def update_baseline(self):
        """Saves the CURRENT list in the UI to the database as the new Baseline."""
        conn = sqlite3.connect("baseline.db")
        cursor = conn.cursor()
        
        # 1. Clear old DB (Crucial! We only want files currently in the UI)
        cursor.execute("DELETE FROM files")
        
        items = self.tree.get_children()
        if not items:
            messagebox.showwarning("Warning", "No files to monitor!")
            return

        # 2. Loop through UI items, calculate hash, insert to DB
        count = 0
        for item in items:
            values = self.tree.item(item)['values']
            filepath = values[0]
            
            if os.path.exists(filepath):
                file_hash = calculate_file_hash(filepath)
                # We INSERT all files currently visible in the UI, creating the new golden record
                cursor.execute("INSERT INTO files (path, hash) VALUES (?, ?)", (filepath, file_hash))
                
                # Update UI to show it's secured
                self.tree.item(item, values=(filepath, "Secured", file_hash), tags=("ok",))
                count += 1
            else:
                # File in list but doesn't exist on disk
                self.tree.item(item, values=(filepath, "Missing", "N/A"), tags=("deleted",))

        conn.commit()
        conn.close()
        messagebox.showinfo("Baseline Updated", f"Successfully secured {count} files in baseline.")

    def scan_files(self):
        """Checks files in the UI against their recorded hash in the DB."""
        conn = sqlite3.connect("baseline.db")
        cursor = conn.cursor()
        
        items = self.tree.get_children()
        
        for item in items:
            values = self.tree.item(item)['values']
            filepath = values[0]
            
            # Get the baseline hash from DB
            cursor.execute("SELECT hash FROM files WHERE path=?", (filepath,))
            result = cursor.fetchone()
            
            if not result:
                # File is in UI but not in DB (User added it but didn't click 'Update Baseline')
                self.tree.item(item, values=(filepath, "Not in Baseline", ""), tags=("new",))
                continue
                
            baseline_hash = result[0]
            
            if not os.path.exists(filepath):
                self.tree.item(item, values=(filepath, "DELETED", baseline_hash), tags=("deleted",))
                continue
            
            current_hash = calculate_file_hash(filepath)
            
            if current_hash == baseline_hash:
                self.tree.item(item, values=(filepath, "OK", current_hash), tags=("ok",))
            else:
                self.tree.item(item, values=(filepath, "MODIFIED", current_hash), tags=("modified",))
                
        conn.close()
        messagebox.showinfo("Scan Complete", "Integrity check finished.")

# --- APP STARTUP ---
if __name__ == "__main__":
    root = tk.Tk()
    app = FIMApp(root)
    root.mainloop()