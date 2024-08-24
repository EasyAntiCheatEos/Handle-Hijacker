Handle Hijack
=============

Overview
--------
Handle Hijack is a C++ utility designed to demonstrate how to hijack handles between processes. This technique can be useful for various tasks like process manipulation and debugging. The program allows you to open handles to processes, duplicate them, and use those handles to read and write memory in a target process.

**Disclaimer:** Use this tool responsibly. Unauthorized access or manipulation of processes can be illegal and unethical.

Features
--------
- Enumerate handles of a process.
- Open handles to processes with various access levels.
- Swap handles between processes.
- Read and write memory in a target process using a hijacked handle.

Requirements
------------
- Windows operating system
- Microsoft Visual Studio or another C++ compiler
- `ntdll.lib` for `NtQuerySystemInformation`

Building
--------
To build Handle Hijack, follow these steps:

1. Clone the Repository:

2. Open the Project:
Open the `HandleHijack.sln` file in Microsoft Visual Studio or your preferred IDE.

3. Build the Project:
Build the project using the Release configuration to produce an executable. Ensure that `ntdll.lib` is available and correctly linked in your project settings.

Usage
-----
The program takes two command-line arguments:

1. Source Process Name: The name of the process from which you want to hijack handles (e.g., `cmd.exe`).
2. Target Process ID: The PID of the process you want to target with the hijacked handle.

Example
-------
To hijack handles from `cmd.exe` and use them in a process with PID `15316`, you would run:


Output
------
The program will:
1. Attempt to find the source process by name.
2. Open handles to both the source and target processes.
3. Swap handles between the processes.
4. Use the stolen handle to read and write memory in the target process.
5. Print the results to the console.

Code Explanation
----------------
- `EnumerateHandles`: Lists all handles of a process.
- `getProcessId`: Retrieves the process ID of a given process name.
- `OpenProcessEx`: Opens a handle to a process with specified access rights.
- `SwapHandles`: Duplicates a handle from the source process to the target process.
- `Read/Write Functions`: Reads from and writes to memory in the target process using the stolen handle.

Important Notes
---------------
- Ensure you have appropriate permissions to access and manipulate the processes.
- The memory addresses used in the `Read` and `Write` functions should be valid for the target process.

License
-------
This project is licensed under the MIT License. See the LICENSE file for more details.

Contact
-------
For questions or issues, please contact [zacherydean@proton.me].
