import ctypes
import psutil
import struct
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import threading
import time
import os

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

data_types = {
    '4-byte Integer': 'i',
    'Float': 'f',
    'Double': 'd',
    'Byte': 'b',
    '2-byte Integer': 'h',
    '8-byte Integer': 'q'
}

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

def write_memory(process_handle, address, value, data_type):
    buffer = ctypes.create_string_buffer(struct.calcsize(data_type))
    struct.pack_into(data_type, buffer, 0, value)
    ctypes.windll.kernel32.WriteProcessMemory(process_handle, address, buffer, len(buffer), None)

def get_memory_regions(pid):
    process_handle = get_process_handle(pid)
    regions = []
    try:
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        while ctypes.windll.kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
                regions.append((mbi.BaseAddress, mbi.RegionSize))
            addr += mbi.RegionSize
    finally:
        ctypes.windll.kernel32.CloseHandle(process_handle)
    return regions

class MemoryEngineApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Engine")
        self.root.geometry("1800x1000")
        self.root.configure(bg="#1e1e1e")

        self.frozen_values = {}
        self.process_handle = None
        self.selected_pid = None
        self.scanned_results = []

        self.setup_ui()

    def setup_ui(self):
        # Top Frame
        top_frame = tk.Frame(self.root, bg="#1e1e1e")
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        self.process_label = tk.Label(top_frame, text="Processes:", font=("Arial", 14), fg="white", bg="#1e1e1e")
        self.process_label.pack(side=tk.LEFT, padx=5)

        self.process_combobox = ttk.Combobox(top_frame, font=("Arial", 12), width=50)
        self.process_combobox.pack(side=tk.LEFT, padx=5)
        self.process_combobox['values'] = self.get_process_list()
        self.process_combobox.bind("<<ComboboxSelected>>", self.process_selected)

        self.refresh_button = tk.Button(top_frame, text="Refresh", command=self.refresh_process_list, bg="#2d2d2d", fg="white", font=("Arial", 12))
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        self.attach_button = tk.Button(top_frame, text="Attach", command=self.attach_process, bg="#2d2d2d", fg="white", font=("Arial", 12))
        self.attach_button.pack(side=tk.LEFT, padx=5)

        self.main_frame = tk.Frame(self.root, bg="#2d2d2d", relief=tk.RIDGE, borderwidth=5)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_panel = tk.Frame(self.main_frame, bg="#2d2d2d")
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        self.memory_regions_label = tk.Label(left_panel, text="Memory Regions:", font=("Arial", 14), fg="white", bg="#2d2d2d")
        self.memory_regions_label.pack(pady=5)

        self.memory_regions_listbox = tk.Listbox(left_panel, font=("Consolas", 12), bg="#1e1e1e", fg="white", selectbackground="#007acc", height=25, width=50)
        self.memory_regions_listbox.pack(fill=tk.BOTH, expand=True)

        self.load_memory_button = tk.Button(left_panel, text="Load Memory Regions", command=self.load_memory_regions, bg="#007acc", fg="white", font=("Arial", 12))
        self.load_memory_button.pack(pady=5)

        middle_panel = tk.Frame(self.main_frame, bg="#2d2d2d")
        middle_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.search_label = tk.Label(middle_panel, text="Search Memory:", font=("Arial", 14), fg="white", bg="#2d2d2d")
        self.search_label.pack(pady=5)

        self.data_type_label = tk.Label(middle_panel, text="Data Type:", font=("Arial", 12), fg="white", bg="#2d2d2d")
        self.data_type_label.pack(pady=5)

        self.data_type_combobox = ttk.Combobox(middle_panel, font=("Arial", 12), values=list(data_types.keys()), state="readonly")
        self.data_type_combobox.pack(pady=5)
        self.data_type_combobox.current(0)

        self.search_entry = tk.Entry(middle_panel, font=("Consolas", 12), width=30, bg="#1e1e1e", fg="white")
        self.search_entry.pack(pady=5)

        self.search_button = tk.Button(middle_panel, text="Search", command=self.search_memory, bg="#007acc", fg="white", font=("Arial", 12))
        self.search_button.pack(pady=5)

        self.search_results_listbox = tk.Listbox(middle_panel, font=("Consolas", 12), bg="#1e1e1e", fg="white", selectbackground="#007acc", height=15)
        self.search_results_listbox.pack(fill=tk.BOTH, expand=True, pady=10)

        self.modify_label = tk.Label(middle_panel, text="Modify Value:", font=("Arial", 14), fg="white", bg="#2d2d2d")
        self.modify_label.pack(pady=5)

        self.modify_entry = tk.Entry(middle_panel, font=("Consolas", 12), width=30, bg="#1e1e1e", fg="white")
        self.modify_entry.pack(pady=5)

        self.modify_button = tk.Button(middle_panel, text="Modify", command=self.modify_memory, bg="#007acc", fg="white", font=("Arial", 12))
        self.modify_button.pack(pady=5)

        self.freeze_button = tk.Button(middle_panel, text="Freeze Value", command=self.freeze_value, bg="#007acc", fg="white", font=("Arial", 12))
        self.freeze_button.pack(pady=10)

        right_panel = tk.Frame(self.main_frame, bg="#2d2d2d")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.pointer_scan_label = tk.Label(right_panel, text="Pointer Scan:", font=("Arial", 14), fg="white", bg="#2d2d2d")
        self.pointer_scan_label.pack(pady=5)

        self.pointer_scan_entry = tk.Entry(right_panel, font=("Consolas", 12), width=30, bg="#1e1e1e", fg="white")
        self.pointer_scan_entry.pack(pady=5)

        self.pointer_scan_button = tk.Button(right_panel, text="Scan", command=self.pointer_scan, bg="#007acc", fg="white", font=("Arial", 12))
        self.pointer_scan_button.pack(pady=5)

        self.pointer_results_listbox = tk.Listbox(right_panel, font=("Consolas", 12), bg="#1e1e1e", fg="white", selectbackground="#007acc", height=10)
        self.pointer_results_listbox.pack(fill=tk.BOTH, expand=True, pady=10)

        self.disassembler_label = tk.Label(right_panel, text="Disassembler:", font=("Arial", 14), fg="white", bg="#2d2d2d")
        self.disassembler_label.pack(pady=5)

        self.disassembler_entry = tk.Entry(right_panel, font=("Consolas", 12), width=30, bg="#1e1e1e", fg="white")
        self.disassembler_entry.pack(pady=5)

        self.disassembler_button = tk.Button(right_panel, text="Disassemble", command=self.disassemble_memory, bg="#007acc", fg="white", font=("Arial", 12))
        self.disassembler_button.pack(pady=5)

        self.disassembler_results_listbox = tk.Listbox(right_panel, font=("Consolas", 12), bg="#1e1e1e", fg="white", selectbackground="#007acc", height=10)
        self.disassembler_results_listbox.pack(fill=tk.BOTH, expand=True, pady=10)

    def get_process_list(self):
        process_list = []
        for proc in psutil.process_iter(['pid', 'name']):
            process_list.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
        return process_list

    def refresh_process_list(self):
        self.process_combobox['values'] = self.get_process_list()

    def process_selected(self, event):
        selected_process = self.process_combobox.get()
        self.selected_pid = int(selected_process.split(" (PID: ")[-1][:-1])

    def attach_process(self):
        if not self.selected_pid:
            messagebox.showerror("Error", "No process selected!")
            return
        try:
            self.process_handle = get_process_handle(self.selected_pid)
            if not self.process_handle:
                raise Exception("Failed to attach to the process.")
            messagebox.showinfo("Success", f"Attached to process with PID {self.selected_pid}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_memory_regions(self):
        if not self.process_handle:
            messagebox.showerror("Error", "Attach to a process first!")
            return
        regions = get_memory_regions(self.selected_pid)
        self.memory_regions_listbox.delete(0, tk.END)
        for base, size in regions:
            self.memory_regions_listbox.insert(tk.END, f"Base: {hex(base)} | Size: {size}")

    def search_memory(self):
        if not self.process_handle:
            messagebox.showerror("Error", "Attach to a process first!")
            return
        data_type = data_types[self.data_type_combobox.get()]
        value = self.search_entry.get()
        if not value:
            messagebox.showerror("Error", "Enter a value to search!")
            return
        try:
            search_value = struct.pack(data_type, eval(value))
            regions = get_memory_regions(self.selected_pid)
            self.scanned_results.clear()
            self.search_results_listbox.delete(0, tk.END)

            for base, size in regions:
                memory = read_memory(self.process_handle, base, size)
                offset = memory.find(search_value)
                while offset != -1:
                    address = base + offset
                    self.scanned_results.append(address)
                    self.search_results_listbox.insert(tk.END, f"Address: {hex(address)}")
                    offset = memory.find(search_value, offset + 1)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def modify_memory(self):
        if not self.process_handle:
            messagebox.showerror("Error", "Attach to a process first!")
            return
        try:
            selected_address = self.search_results_listbox.get(tk.ACTIVE)
            if not selected_address:
                messagebox.showerror("Error", "No address selected!")
                return
            address = int(selected_address.split("Address: ")[-1], 16)
            new_value = self.modify_entry.get()
            if not new_value:
                messagebox.showerror("Error", "Enter a value to modify!")
                return
            data_type = data_types[self.data_type_combobox.get()]
            write_memory(self.process_handle, address, eval(new_value), data_type)
            messagebox.showinfo("Success", f"Modified address {hex(address)} to {new_value}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def freeze_value(self):
        try:
            selected_address = self.search_results_listbox.get(tk.ACTIVE)
            if not selected_address:
                messagebox.showerror("Error", "No address selected!")
                return
            address = int(selected_address.split("Address: ")[-1], 16)
            value_to_freeze = self.modify_entry.get()
            if not value_to_freeze:
                messagebox.showerror("Error", "Enter a value to freeze!")
                return
            data_type = data_types[self.data_type_combobox.get()]
            self.frozen_values[address] = (eval(value_to_freeze), data_type)
            threading.Thread(target=self.freeze_loop, daemon=True).start()
            messagebox.showinfo("Success", f"Value at address {hex(address)} is now frozen.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def freeze_loop(self):
        while self.frozen_values:
            for address, (value, data_type) in self.frozen_values.items():
                try:
                    write_memory(self.process_handle, address, value, data_type)
                except Exception:
                    pass
            time.sleep(0.1)

    def pointer_scan(self):
        messagebox.showinfo("Info", "Pointer scan functionality is under construction.")

    def disassemble_memory(self):
        messagebox.showinfo("Info", "Disassembler functionality is under construction.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MemoryEngineApp(root)
    root.mainloop()
