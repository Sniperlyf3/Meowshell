#!/usr/bin/env bash
# Build a throwaway app against the packages in ./nupkg and check that it
# finds and runs the binaries with nothing but a PackageReference to
# Meowshell itself -- Meowshell.Runtime.linux is never added here; it
# only reaches this app as a transitive dependency of a package built with
# -p:IncludeRuntimeDependencies=true, which is exactly the point. Packing
# successfully proves very little: only consuming the package catches a
# broken layout (e.g. NuGet reading an extension-less PackagePath as a
# directory instead of a file).
set -euo pipefail

feed=${FEED:-$PWD/nupkg}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The version is computed at pack time (Directory.Build.props), not fixed
# here, so discover it from what actually got packed rather than hardcoding
# it -- also pins to that exact version, not a floating range, since the
# nuget.config below still includes the public nuget.org source.
pkg=$(basename "$feed"/Meowshell.[0-9]*.nupkg)
version=${pkg#Meowshell.}
version=${version%.nupkg}
[ -n "$version" ] || { echo "no Meowshell.*.nupkg found in $feed" >&2; exit 1; }

cd "$work"
cat > nuget.config <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$feed" />
    <add key="nuget" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
EOF

dotnet new console -o App -n App --force > /dev/null
cat > App/Program.cs <<'EOF'
using System.Diagnostics;
using Meowshell;

var dir = BinaryLocator.Locate(BinaryNaming.ForCurrentPlatform());
if (dir is null)
{
    Console.Error.WriteLine($"no binaries for {BinaryLocator.RuntimeIdentifier}; looked in:");
    foreach (var d in BinaryLocator.SearchPath(AppContext.BaseDirectory))
        Console.Error.WriteLine($"  {d}");
    return 1;
}
Console.WriteLine($"located {BinaryLocator.RuntimeIdentifier} binaries in {dir}");

// Run the thing, not just find it: a file without the executable bit
// resolves fine and then fails to start.
var exe = Path.Combine(dir, BinaryNaming.ForCurrentPlatform().FileName("tailcat"));
var p = Process.Start(new ProcessStartInfo(exe, "version") { RedirectStandardOutput = true })!;
var version = p.StandardOutput.ReadToEnd().Trim();
p.WaitForExit();
if (p.ExitCode != 0 || version.Length == 0)
{
    Console.Error.WriteLine($"tailcat did not run (exit {p.ExitCode})");
    return 1;
}
Console.WriteLine($"ran the packaged tailcat: {version}");
return 0;
EOF

cd App
dotnet add package Meowshell --version "$version" > /dev/null
dotnet run
