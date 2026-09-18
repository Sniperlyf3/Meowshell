#nullable enable

namespace Meowshell;

/// <summary>
/// Supported entry point for a consumer that manages its own storage layout -- an Android app choosing
/// a child of <c>FilesDir</c>, a service using a systemd <c>RuntimeDirectory</c> -- and wants a path
/// prepared the same private, owner-only way this library prepares its own
/// <see cref="TailcatOptions.HomeDirectory"/>/<see cref="MeowshellOptions.WorkDirectory"/>, without
/// re-implementing the symlink rejection, the race-safe re-read after create, the Windows ACL check, and
/// the narrowing of a pre-existing over-permissive directory. Before this, <c>MeowshellHomeDirectory</c>
/// (the internal type doing the actual work) was not exposed at all, so a caller in this position had to
/// duplicate that security-sensitive logic itself or accept getting it subtly wrong with no signal
/// (home-directory-upgrade spec, "why the caller cannot simply fix it themselves").
/// </summary>
public static class MeowshellHome
{
    /// <summary>
    /// Creates <paramref name="path"/> as a private, owner-only directory if it doesn't exist, or
    /// verifies and repairs a pre-existing one, then returns <paramref name="path"/> unchanged for
    /// convenient chaining (e.g. <c>HomeDirectory = MeowshellHome.Prepare(myPath)</c>).
    /// </summary>
    /// <exception cref="IOException">
    /// <paramref name="path"/> is a symlink/reparse point, already exists as a file, or is accessible to
    /// other users and either isn't owned by the current user (Unix: the narrowing <c>chmod</c> failed) or
    /// grants an untrusted principal access (Windows) and so cannot be narrowed.
    /// </exception>
    public static string Prepare(string path)
    {
        MeowshellHomeDirectory.EnsureSecure(path);
        return path;
    }
}
