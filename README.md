#Code_Injector


# Advanced Shellcode Injector

## **Overview**
This script is an advanced shellcode injector that injects and executes shellcode inside a target process without requiring a DLL. It uses `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` to achieve direct shellcode execution.

⚠ **Disclaimer:** This script is for educational and ethical penetration testing purposes only. Unauthorized use on systems without permission is illegal.

---

## **Features**
- Injects raw shellcode into a target process
- Uses `CreateRemoteThread` for execution
- Can be modified to execute custom payloads
- Works on Windows
- Bypasses traditional DLL injection detection

---

## **Installation**
### **Step 1: Install Dependencies**
This script requires Python and `psutil`:
```bash
pip install psutil
```

---

## **Usage**
### **Step 2: Run the Injector**
```bash
python injector.py <process_name.exe>
```
Example:
```bash
python injector.py notepad.exe
```
This will inject the shellcode into `notepad.exe`.

---

## **How It Works**
1. **Finds the Target Process** using `psutil` to obtain the PID.
2. **Opens the Process Handle** using `OpenProcess()`.
3. **Allocates Memory** in the target process using `VirtualAllocEx()`.
4. **Writes Shellcode** into the allocated memory using `WriteProcessMemory()`.
5. **Executes Shellcode** using `CreateRemoteThread()`.

---

## **Modifying the Shellcode**
The current shellcode spawns `calc.exe`. You can modify it with your own payload.
Replace this line in `injector.py`:
```python
SHELLCODE = b"\x31\xc0\x50\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe6\x50\x56\xff\xd0"
```
with your own shellcode.

---

## **Advanced Techniques**
- **Process Hollowing**: Replace a running process with your own payload.
- **Reflective DLL Injection**: Load DLLs from memory instead of disk.
- **Direct Syscalls**: Evade detection from security tools.
- **Self-Deletion**: Remove traces after execution.

---

## **Legal Disclaimer**
This tool is intended for **ethical hacking, cybersecurity research, and penetration testing** only. **Unauthorized use on unauthorized systems is illegal** and can result in severe penalties. The author is not responsible for any misuse or damage caused by this tool.

---

## **Author**
**Security Researcher & Ethical Hacker**

For educational purposes only!

