from __future__ import annotations

import ctypes
import os
import subprocess
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from pathlib import Path

from .base import IsolationError

ERROR_ALREADY_EXISTS = 183
ERROR_INSUFFICIENT_BUFFER = 122
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_SUSPENDED = 0x00000004
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
INFINITE = 0xFFFFFFFF


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", ctypes.c_void_p),
        ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION_STRUCT(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _raise_last_error(operation: str) -> None:
    error = ctypes.get_last_error()
    raise IsolationError(f"{operation} failed: {ctypes.WinError(error)}")


def _hresult_code(value: int) -> int:
    return value & 0xFFFFFFFF


class WindowsNativeAppContainer:
    def __init__(self) -> None:
        if os.name != "nt":
            raise IsolationError("Windows AppContainer is only available on Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self.userenv = ctypes.WinDLL("userenv", use_last_error=True)
        self._configure_signatures()

    def _configure_signatures(self) -> None:
        self.userenv.CreateAppContainerProfile.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.POINTER(SID_AND_ATTRIBUTES),
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.userenv.CreateAppContainerProfile.restype = ctypes.c_long
        self.userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
        self.userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
        self.userenv.DeleteAppContainerProfile.restype = ctypes.c_long
        self.advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        self.advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        self.kernel32.InitializeProcThreadAttributeList.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        self.kernel32.UpdateProcThreadAttribute.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
        self.kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
        self.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel32.LocalFree.restype = ctypes.c_void_p
        self.advapi32.FreeSid.argtypes = [ctypes.c_void_p]
        self.advapi32.FreeSid.restype = ctypes.c_void_p
        self.kernel32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(STARTUPINFOW),
            ctypes.POINTER(PROCESS_INFORMATION),
        ]
        self.kernel32.CreateProcessW.restype = wintypes.BOOL
        self.kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self.kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        self.kernel32.ResumeThread.restype = wintypes.DWORD
        self.kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        self.kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel32.TerminateProcess.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL

    def create_profile(self, name: str) -> ctypes.c_void_p:
        sid = ctypes.c_void_p()
        result = self.userenv.CreateAppContainerProfile(
            name,
            "Interpose agent session",
            "Network-isolated Interpose session",
            None,
            0,
            ctypes.byref(sid),
        )
        if result == 0:
            return sid
        if _hresult_code(result) == 0x80070000 | ERROR_ALREADY_EXISTS:
            derive_result = self.userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(sid))
            if derive_result == 0:
                return sid
            raise IsolationError(
                "DeriveAppContainerSidFromAppContainerName failed: "
                f"0x{_hresult_code(derive_result):08x}"
            )
        raise IsolationError(f"CreateAppContainerProfile failed: 0x{_hresult_code(result):08x}")

    def derive_profile_sid(self, name: str) -> ctypes.c_void_p:
        sid = ctypes.c_void_p()
        result = self.userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(sid))
        if result != 0:
            raise IsolationError(f"DeriveAppContainerSidFromAppContainerName failed: 0x{_hresult_code(result):08x}")
        return sid

    def delete_profile(self, name: str) -> None:
        result = self.userenv.DeleteAppContainerProfile(name)
        if result != 0:
            raise IsolationError(f"DeleteAppContainerProfile failed: 0x{_hresult_code(result):08x}")

    def sid_to_string(self, sid: ctypes.c_void_p) -> str:
        output = wintypes.LPWSTR()
        if not self.advapi32.ConvertSidToStringSidW(sid, ctypes.byref(output)):
            _raise_last_error("ConvertSidToStringSidW")
        try:
            return output.value
        finally:
            self.kernel32.LocalFree(ctypes.cast(output, ctypes.c_void_p))

    def free_sid(self, sid: ctypes.c_void_p) -> None:
        self.advapi32.FreeSid(sid)

    def launch(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        appcontainer_sid: ctypes.c_void_p,
    ) -> int:
        attribute_size = ctypes.c_size_t()
        self.kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attribute_size))
        if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
            _raise_last_error("InitializeProcThreadAttributeList(size)")
        attribute_buffer = ctypes.create_string_buffer(attribute_size.value)
        attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
        if not self.kernel32.InitializeProcThreadAttributeList(attribute_list, 1, 0, ctypes.byref(attribute_size)):
            _raise_last_error("InitializeProcThreadAttributeList")

        security_capabilities = SECURITY_CAPABILITIES(
            AppContainerSid=appcontainer_sid,
            Capabilities=None,
            CapabilityCount=0,
            Reserved=0,
        )
        if not self.kernel32.UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(security_capabilities),
            ctypes.sizeof(security_capabilities),
            None,
            None,
        ):
            self.kernel32.DeleteProcThreadAttributeList(attribute_list)
            _raise_last_error("UpdateProcThreadAttribute")

        startup = STARTUPINFOEXW()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.lpAttributeList = attribute_list
        process_info = PROCESS_INFORMATION()
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(list(command)))
        environment_text = "\0".join(f"{key}={value}" for key, value in sorted(environment.items())) + "\0\0"
        environment_buffer = ctypes.create_unicode_buffer(environment_text)
        job = self._create_kill_on_close_job()

        try:
            created = self.kernel32.CreateProcessW(
                None,
                command_line,
                None,
                None,
                False,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                environment_buffer,
                str(cwd),
                ctypes.byref(startup.StartupInfo),
                ctypes.byref(process_info),
            )
            if not created:
                _raise_last_error("CreateProcessW(AppContainer)")
            if not self.kernel32.AssignProcessToJobObject(job, process_info.hProcess):
                self.kernel32.TerminateProcess(process_info.hProcess, 1)
                _raise_last_error("AssignProcessToJobObject")
            if self.kernel32.ResumeThread(process_info.hThread) == 0xFFFFFFFF:
                self.kernel32.TerminateProcess(process_info.hProcess, 1)
                _raise_last_error("ResumeThread")
            self.kernel32.WaitForSingleObject(process_info.hProcess, INFINITE)
            exit_code = wintypes.DWORD()
            if not self.kernel32.GetExitCodeProcess(process_info.hProcess, ctypes.byref(exit_code)):
                _raise_last_error("GetExitCodeProcess")
            return int(exit_code.value)
        finally:
            if process_info.hThread:
                self.kernel32.CloseHandle(process_info.hThread)
            if process_info.hProcess:
                self.kernel32.CloseHandle(process_info.hProcess)
            self.kernel32.CloseHandle(job)
            self.kernel32.DeleteProcThreadAttributeList(attribute_list)

    def _create_kill_on_close_job(self) -> wintypes.HANDLE:
        job = self.kernel32.CreateJobObjectW(None, None)
        if not job:
            _raise_last_error("CreateJobObjectW")
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION_STRUCT()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            self.kernel32.CloseHandle(job)
            _raise_last_error("SetInformationJobObject")
        return job
