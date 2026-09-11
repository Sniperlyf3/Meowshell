#nullable enable
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Meowshell;

[SupportedOSPlatform("windows")]
internal sealed class JobObject : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }

    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateJobObjectW(nint lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        SafeHandle hJob, int jobObjectInfoClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeHandle hJob, SafeHandle hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(SafeHandle processHandle, SafeHandle jobHandle, out bool result);

    private readonly SafeFileHandle _handle;

    public string? Name { get; }

    private JobObject(SafeFileHandle handle, string? name)
    {
        _handle = handle;
        Name = name;
    }

    public static JobObject CreateForChild()
    {
        // Named before Process.Start so the child can join itself at the first
        // line of main, eliminating the Start()->AssignProcessToJobObject race
        // where it could otherwise spawn a grandchild before the parent got to
        // attach it.
        var name = $@"Local\Meowshell-{Guid.NewGuid():N}";
        return Create(name);
    }

    private static JobObject Create(string? name)
    {
        var handle = CreateJobObjectW(0, name);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "creating Windows Job Object");

        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
        };
        var infoSize = (uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformation, ref info, infoSize))
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "configuring Windows Job Object");
        }
        return new JobObject(handle, name);
    }

    public void EnsureAssigned(Process process)
    {
        if (IsAssigned(process)) return;

        if (!AssignProcessToJobObject(_handle, process.SafeHandle))
        {
            var error = Marshal.GetLastWin32Error();
            // The child may have raced us only in the safe direction and
            // already joined this exact named job from main(). Re-check before
            // treating the native failure as fatal.
            if (IsAssigned(process)) return;
            throw new Win32Exception(error, "assigning child process to Windows Job Object");
        }
    }

    internal bool IsAssigned(Process process)
    {
        if (!IsProcessInJob(process.SafeHandle, _handle, out var result))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "querying Windows Job Object membership");
        return result;
    }

    public static JobObject Wrap(Process process)
    {
        var job = Create(name: null);
        try
        {
            job.EnsureAssigned(process);
            return job;
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    public void Dispose() => _handle.Dispose();
}
