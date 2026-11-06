using System.Text.RegularExpressions;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// <see cref="EpoxideRuntime.Version"/> reports the version the package was built as.
/// </summary>
/// <remarks>
/// ioxide's used to be a hand-kept literal, and literals rot: it read "0.0.17" against packages on
/// 0.13.233 (ioxide's #224). epoxide's is generated from epoxide.csproj's Version property the same
/// way, so the test worth having compares it against that property - if the generator stops
/// running, or someone puts a literal in, these fail.
///
/// No reflection anywhere here, deliberately: the whole reason the version is generated rather than
/// read off AssemblyInformationalVersionAttribute is that Native AOT trims attribute reflection, and
/// a test that reached for it would be testing something the shipped configuration cannot do.
/// </remarks>
internal static class VersionTests
{
    public static void Register(Runner runner)
    {
        runner.Test("version: EpoxideRuntime.Version matches epoxide.csproj", () =>
        {
            string csproj = FindCsproj();
            Match declared = Regex.Match(File.ReadAllText(csproj), @"<Version>([^<]+)</Version>");

            Assert.True(declared.Success, $"no <Version> element in {csproj}");
            Assert.Equal(declared.Groups[1].Value, EpoxideRuntime.Version);
        });

        runner.Test("version: it is a real version, not a placeholder", () =>
        {
            Assert.True(EpoxideRuntime.Version.Length > 0, "Version is empty");

            Assert.True(Version.TryParse(EpoxideRuntime.Version, out Version? parsed) && parsed is not null,
                $"Version is not parseable: '{EpoxideRuntime.Version}'");

            Assert.True(parsed!.Major > 0 || parsed.Minor > 0 || parsed.Build > 0,
                $"Version is all zeroes: '{EpoxideRuntime.Version}'");
        });

        runner.Test("version: no build metadata leaks into it", () =>
        {
            // The SDK appends "+<commit sha>" to the informational version from the repository's git
            // metadata - an assembly attribute reads like "0.1.0+c169a2b...". Generating the
            // const from the Version property sidesteps that entirely, and this pins it: callers
            // compare the value against a package version, and no package is named with a sha on it.
            Assert.True(!EpoxideRuntime.Version.Contains('+'),
                $"build metadata reached the reported version: '{EpoxideRuntime.Version}'");
        });
    }

    /// <summary>
    /// Walks up from the test binary to the repo root, identified by the solution file beside it.
    /// Plain file system, no reflection - see the note on the class.
    /// </summary>
    private static string FindCsproj()
    {
        for (DirectoryInfo? at = new(AppContext.BaseDirectory); at is not null; at = at.Parent)
        {
            if (File.Exists(Path.Combine(at.FullName, "ioxide.slnx")))
            {
                string csproj = Path.Combine(at.FullName, "src", "epoxide", "epoxide.csproj");

                Assert.True(File.Exists(csproj), $"found the repo root at {at.FullName} but no {csproj}");
                return csproj;
            }
        }

        throw new Exception(
            $"no ioxide.slnx above {AppContext.BaseDirectory} - this test reads the version out of the repo");
    }
}
