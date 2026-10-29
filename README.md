# OS-Internals

Personal study notes, architectural breakdowns, memory/register traces, and hands-on C/C++ & x64 MASM labs exploring Operating System Internals from first principles.

---

## Windows x64 Internals (`windows/`)

All labs are compiled natively on Windows 11 x64 (`cl.exe` / `ml64.exe`) and verified in **x64dbg**, **WinDbg**, **System Informer**, and **PE-bear**.

### Phase 1: The Architecture & Memory Model
| Module | Study Notes | Hands-On Lab | Core Topics |
| :--- | :--- | :--- | :--- |
| **1.1** | [`01-call-chain-and-ntapi.md`](windows/01-call-chain-and-ntapi.md) | [`lab-1.1`](windows/labs/lab-1.1/) | Ring 3 vs. Ring 0, Subsystems, `kernel32` $\rightarrow$ `kernelbase` $\rightarrow$ `ntdll` $\rightarrow$ `syscall`, `NTSTATUS` |
| **1.2** | [`02-virtual-memory-and-permissions.md`](windows/02-virtual-memory-and-permissions.md) | [`lab-1.2`](windows/labs/lab-1.2/) | Virtual Address Space, Page Tables, VADs, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, DEP/NX |
| **1.3** | [`03-peb-teb-and-ldr-walking.md`](windows/03-peb-teb-and-ldr-walking.md) | [`lab-1.3`](windows/labs/lab-1.3/) | `GS` segment register (`gs:[0x30]` / `gs:[0x60]`), `TEB`, `PEB`, `PEB_LDR_DATA` doubly-linked list walking |

### Phase 2: The Portable Executable (PE) File Format
| Module | Study Notes | Hands-On Lab | Core Topics |
| :--- | :--- | :--- | :--- |
| **2.1** | [`04-pe-headers-and-sections.md`](windows/04-pe-headers-and-sections.md) | [`lab-2.1`](windows/labs/lab-2.1/) | DOS/NT/Section Headers, `FileAlignment` (`0x200`) vs. `SectionAlignment` (`0x1000`), RVA-to-File-Offset math |
| **2.2** | [`05-eat-getprocaddress-and-api-hashing.md`](windows/05-eat-getprocaddress-and-api-hashing.md) | [`lab-2.2`](windows/labs/lab-2.2/) | `IMAGE_EXPORT_DIRECTORY` (EAT), Export Forwarding, Custom `GetProcAddress`, DJB2 API Hashing |
| **2.3** | [`06-iat-relocations-and-hooking.md`](windows/06-iat-relocations-and-hooking.md) | [`lab-2.3`](windows/labs/lab-2.3/) | `IMAGE_IMPORT_DESCRIPTOR`, ILT vs. IAT (`OriginalFirstThunk` / `FirstThunk`), `.reloc` (`DIR64`), IAT Hooking |

### Phase 3: Processes, Handles, Tokens & Cross-Process Primitives
| Module | Study Notes | Hands-On Lab | Core Topics |
| :--- | :--- | :--- | :--- |
| **3.1** | [`07-objects-handles-and-process-enum.md`](windows/07-objects-handles-and-process-enum.md) | [`lab-3.1`](windows/labs/lab-3.1/) | Kernel Object Manager, `EPROCESS`, Handle Tables, Access Masks, `NtQuerySystemInformation`, `NtOpenProcess` |
| **3.2** | [`08-cross-process-primitives.md`](windows/08-cross-process-primitives.md) | [`lab-3.2`](windows/labs/lab-3.2/) | Shared Section Objects (`NtCreateSection` / `NtMapViewOfSection`), `NtCreateThreadEx`, APCs & Thread Contexts |
| **3.3** | [`09-tokens-sids-and-privileges.md`](windows/09-tokens-sids-and-privileges.md) | [`lab-3.3`](windows/labs/lab-3.3/) | Access Tokens, SIDs, `SeDebugPrivilege` (`NtAdjustPrivilegesToken`), Token Duplication & `SYSTEM` Impersonation |

### Phase 4: Advanced Loader & Evasion Internals
| Module | Study Notes | Hands-On Lab | Core Topics |
| :--- | :--- | :--- | :--- |
| **4.1** | [`10-reflective-pe-loading.md`](windows/10-reflective-pe-loading.md) | [`lab-4.1`](windows/labs/lab-4.1/) | Reflective PE Loading / Manual Mapping, Zero-`LoadLibrary`/`GetProcAddress`, Per-Section `RX`/`R`/`RW` Locking |
| **4.2** | [`11-usermode-hooks-and-syscalls.md`](windows/11-usermode-hooks-and-syscalls.md) | [`lab-4.2`](windows/labs/lab-4.2/) | PatchGuard, Inline `0xE9` Hooks, Dynamic SSN Recovery (Hell's Gate / Halo's Gate), Direct vs. Indirect Syscalls |
| **4.3** | [`12-call-stack-spoofing-pdata-and-etw-amsi.md`](windows/12-call-stack-spoofing-pdata-and-etw-amsi.md) | [`lab-4.3`](windows/labs/lab-4.3/) | x64 `.pdata` (`RUNTIME_FUNCTION` & `UNWIND_INFO`), Synthetic Stack Frames, `KernelBase.dll` Gadget Call Stack Spoofing, ETW/AMSI |
