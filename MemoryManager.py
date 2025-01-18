import ctypes
import psutil
import struct
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import time
import threading

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000  # Memory state for committed memory

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]

def get_process_handle(pid):
    return ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

def read_memory(process_handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ctypes.windll.kernel32.ReadProcessMemory(process_handle, address, buffer, size, ctypes.byref(bytes_read))
    return buffer.raw
  
def write_memory(process_handle, address, value, size):
    buffer = ctypes.create_string_buffer(size)
    if isinstance(value, int):
        struct.pack_into('I', buffer, 0, value)
    elif isinstance(value, float):
        struct.pack_into('f', buffer, 0, value)
    ctypes.windll.kernel32.WriteProcessMemory(process_handle, address, buffer, size, None)

def get_memory_regions(pid):
    process_handle = get_process_handle(pid)
    regions = []
    try:
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        while ctypes.windll.kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == MEM_COMMIT:  # Check if the memory is committed
                regions.append((mbi.BaseAddress, mbi.RegionSize))
            addr += mbi.RegionSize  # Move to the next region
    finally:
        ctypes.windll.kernel32.CloseHandle(process_handle)
    return regions

def get_process_icon(pid):
    try:
        process = psutil.Process(pid)
        icon = process.icon()
        return icon
    except Exception:
        return None

class MemoryEngineApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Engine")
        self.root.geometry("1200x800")  # Set a larger window size
        
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.process_label = tk.Label(self.main_frame, text="Select Process:", font=("Arial", 16))
        self.process_label.pack(pady=5)
        
        self.process_combobox = ttk.Combobox(self.main_frame, values=self.get_process_list(), font=("Arial", 14))
        self.process_combobox.pack(pady=5, fill=tk.X)
        self.process_combobox.bind("<<ComboboxSelected>>", self.update_process_icon)

        self.icon_label = tk.Label(self.main_frame)
        self.icon_label.pack(pady=5)
      
        self.memory_label = tk.Label(self.main_frame, text="Memory Regions:", font=("Arial", 16))
        self.memory_label.pack(pady=5)

        self.memory_canvas = tk.Canvas(self.main_frame)
        self.memory_scrollbar = ttk.Scrollbar(self.main_frame, orient="vertical", command=self.memory_canvas.yview)
        self.memory_frame = tk.Frame(self.memory_canvas)

        self.memory_frame.bind("<Configure>", lambda e: self.memory_canvas.configure(scrollregion=self.memory_canvas.bbox("all")))

        self.memory_canvas.create_window((0, 0), window=self.memory_frame, anchor="nw")
        self.memory_canvas.configure(yscrollcommand=self.memory_scrollbar.set)

        self.memory_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.memory_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
      
        self.load_button = tk.Button(self.main_frame, text="Load Memory Regions", command=self.load_memory_regions, font=("Arial", 12))
        self.load_button.pack(pady=10)

        self.search_label = tk.Label(self.main_frame, text="Search Value:", font=("Arial", 14))
        self.search_label.pack(pady=5)

        self.search_entry = tk.Entry(self.main_frame, font=("Arial", 12))
        self.search_entry.pack(pady=5, fill=tk.X)

        self.search_button = tk.Button(self.main_frame, text="Search", command=self.search_memory, font=("Arial", 12))
        self.search_button.pack(pady=10)

        self.modify_label = tk.Label(self.main_frame, text="Modify Value:", font=("Arial", 14))
        self.modify_label.pack(pady=5)

        self.modify_entry = tk.Entry(self.main_frame, font=("Arial", 12))
        self.modify_entry.pack(pady=5, fill=tk.X)

        self.modify_button = tk.Button(self.main_frame, text="Modify", command=self.modify_memory, font=("Arial", 12))
        self.modify_button.pack(pady=10)

        self.freeze_button = tk.Button(self.main_frame, text="Freeze Value", command=self.freeze_value, font=("Arial", 12))
        self.freeze_button.pack(pady=10)

        self.version_button = tk.Button(self.main_frame, text="Get CE Version", command=self.get_ce_version, font=("Arial", 12))
        self.version_button.pack(pady=10)

        self.frozen_values = {}

    def get_process_list(self):
        process_list = []
        for proc in psutil.process_iter(['pid', 'name']):
            # Exclude known system processes
            if proc.info['name'] not in ['System Idle Process', 'System', 'explorer.exe', 'svchost.exe']:
                process_list.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
        return process_list

    def update_process_icon(self, event):

        selected_process = self.process_combobox.get()
        pid = int(selected_process.split(" (PID: ")[-1][:-1])
        icon = get_process_icon(pid)
        if icon:
            icon_image = ImageTk.PhotoImage(icon)
            self.icon_label.config(image=icon_image)
            self.icon_label.image = icon_image  
        else:
            self.icon_label.config(image='')

    def load_memory_regions(self):
        selected_process = self.process_combobox.get()
        pid = int(selected_process.split(" (PID: ")[-1][:-1])
        self.clear_memory_display()

        memory_regions = get_memory_regions(pid)
        for base_address, region_size in memory_regions:
            address_label = tk.Label(self.memory_frame, text=f"Base Address: {hex(base_address)} | Size: {region_size}", font=("Arial", 12))
            address_label.pack(anchor="w")

    def clear_memory_display(self):
        for widget in self.memory_frame.winfo_children():
            widget.destroy()

    def search_memory(self):
        selected_process = self.process_combobox.get()
        pid = int(selected_process.split(" (PID: ")[-1][:-1])
        search_value = self.search_entry.get()
        if not search_value:
            messagebox.showwarning("Input Error", "Please enter a value to search.")
            return
          
        messagebox.showinfo("Search", f"Searching for value: {search_value} in process PID: {pid}")

    def modify_memory(self):
        selected_process = self.process_combobox.get()
        pid = int(selected_process.split(" (PID: ")[-1][:-1])
        modify_value = self.modify_entry.get()
        if not modify_value:
            messagebox.showwarning("Input Error", "Please enter a value to modify.")
            return

        messagebox.showinfo("Modify", f"Modifying value to: {modify_value} in process PID: {pid}")

    def freeze_value(self):
        selected_process = self.process_combobox.get()
        pid = int(selected_process.split(" (PID: ")[-1][:-1])
        freeze_value = self.modify_entry.get()
        if not freeze_value:
            messagebox.showwarning("Input Error", "Please enter a value to freeze.")
            return

        self.frozen_values[pid] = freeze_value
        messagebox.showinfo("Freeze", f"Value {freeze_value} is now frozen in process PID: {pid}")

    def get_ce_version(self):
        # Placeholder for actual version retrieval logic
        messagebox.showinfo("Version", "Memory Manager Version: 1.0.1")

if __name__ == "__main__":
    root = tk.Tk()
    app = MemoryEngineApp(root)
    root.mainloop()
