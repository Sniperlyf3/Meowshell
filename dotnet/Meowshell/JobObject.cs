#nullable enable
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Meowshell;

/// <summary>
/// A Windows job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: the OS kills
/// every process assigned to it as soon as this handle closes, including
/// when the owning process itself crashes and the kernel closes its handles
/// for it. Windows has no exec(), so meowshell stays as a separate parent of
/// tailcat rather than becoming it; if the host process dies before
/// MeowshellServer's own shutdown code runs, this is what stops tailcat
/// surviving as an orphan. Assigning meowshell to the job is enough --
/// tailcat, started later as meowshell's child, joins the same job by
/// Windows' default nesting behavior.
/// </summary>
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

    private readonly SafeFileHandle _handle;

    private JobObject(SafeFileHandle handle) => _handle = handle;

    /// <summary>
    /// Creates a kill-on-close job object and assigns <paramref name="process"/>
    /// to it. Returns null if the OS refuses (e.g. the process already
    /// belongs to a job that forbids further nesting) -- the deadline and
    /// the orderly stop/kill path still apply either way; this is only a
    /// backstop for a crash.
    /// </summary>
    public static JobObject? Wrap(Process process)
    {
        var handle = CreateJobObjectW(0, null);
        if (handle.IsInvalid) return null;

        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
        };
        var infoSize = (uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformation, ref info, infoSize)
            || !AssignProcessToJobObject(handle, process.SafeHandle))
        {
            handle.Dispose();
            return null;
        }
        return new JobObject(handle);
    }

    public void Dispose() => _handle.Dispose();
}
