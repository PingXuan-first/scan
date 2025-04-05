import psutil
import time
import os
import sys
import ctypes
from ctypes import c_uint, c_void_p, c_size_t, c_int  # 添加 c_int 导入

# 加载 macOS 的 Mach API
libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib')

# Mach API 函数定义
mach_task_self = libc.mach_task_self
mach_task_self.argtypes = []
mach_task_self.restype = c_uint

task_for_pid = libc.task_for_pid
task_for_pid.argtypes = [c_uint, c_uint, c_void_p]
task_for_pid.restype = c_int  # 使用 c_int

mach_vm_write = libc.mach_vm_write
mach_vm_write.argtypes = [c_uint, c_void_p, c_void_p, c_size_t]
mach_vm_write.restype = c_int  # 使用 c_int

def clear_screen():
    os.system('clear')

def get_process_info():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            if proc.info['memory_info'] is None:
                continue
            mem = proc.info['memory_info'].rss / 1024 / 1024  # 转换为 MB
            processes.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'memory_mb': mem
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
    return sorted(processes, key=lambda x: x['memory_mb'], reverse=True)

def modify_memory(pid, address, value):
    try:
        current_task = mach_task_self()
        target_task = c_uint()
        ret = task_for_pid(current_task, pid, ctypes.byref(target_task))
        if ret != 0:
            print(f"Failed to get task for PID {pid}. Error: {ret}. Run with sudo.")
            return False
        
        data = ctypes.c_int(int(value))  # 使用 c_int
        data_size = ctypes.sizeof(data)
        ret = mach_vm_write(target_task, address, ctypes.byref(data), data_size)
        if ret != 0:
            print(f"Failed to write to memory at {hex(address)}. Error: {ret}")
            return False
        
        print(f"Successfully wrote {value} to PID {pid} at address {hex(address)}")
        return True
    except Exception as e:
        print(f"Error modifying memory: {e}")
        return False

def display_processes():
    while True:
        clear_screen()
        processes = get_process_info()
        
        print(f"{'PID':<10} {'Name':<30} {'Memory (MB)':<15}")
        print("-" * 55)
        for proc in processes[:10]:
            print(f"{proc['pid']:<10} {proc['name']:<30} {proc['memory_mb']:<15.2f}")
        
        total_memory = psutil.virtual_memory()
        print("\nSystem Memory Usage:")
        print(f"Total: {total_memory.total / 1024 / 1024:.2f} MB")
        print(f"Used: {total_memory.used / 1024 / 1024:.2f} MB")
        print(f"Free: {total_memory.free / 1024 / 1024:.2f} MB")
        
        print("\nEnter 'm' to modify memory, or press Ctrl+C to exit.")
        choice = input("> ").strip().lower()
        
        if choice == 'm':
            pid = input("Enter PID to modify: ")
            address = input("Enter memory address (hex, e.g., 0x1000000): ")
            value = input("Enter value to write (integer): ")
            try:
                pid = int(pid)
                address = int(address, 16)
                value = int(value)
                modify_memory(pid, address, value)
                input("Press Enter to continue...")
            except ValueError:
                print("Invalid input. PID, address, and value must be valid numbers.")
                input("Press Enter to continue...")
        
        time.sleep(1)

if __name__ == "__main__":
    try:
        print("Starting memory monitor... (Press Ctrl+C to exit)")
        time.sleep(1)
        display_processes()
    except KeyboardInterrupt:
        print("\nStopped by user.")
        sys.exit(0)
