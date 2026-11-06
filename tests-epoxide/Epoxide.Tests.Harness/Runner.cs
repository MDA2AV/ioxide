namespace Epoxide.Tests;

/// <summary>Tiny test runner: PASS / FAIL / SKIP per test, a summary line, and a non-zero exit on failure.</summary>
public sealed class Runner
{
    /// <summary>
    /// How long any one test may run before it is called hung. Generous, because several tests
    /// wait out acquire budgets and cooldowns on purpose - this is a backstop against a wedged
    /// read, not a performance bar.
    /// </summary>
    private const int DefaultTimeoutMs = 120_000;

    // A suite's first command-line argument: only the tests whose name contains it run.
    private readonly string? _filter;

    private int _passed;
    private int _failed;
    private int _skipped;
    private int _pending;
    private int _knownBugs;

    /// <param name="args">
    /// The suite's command line. One argument runs only the tests whose name contains it -
    /// <c>dotnet run --project tests-epoxide/Epoxide.Tests.E2E -- "threadpool:"</c>.
    /// </param>
    public Runner(string[]? args = null)
    {
        _filter = args is { Length: > 0 } && args[0].Length > 0 ? args[0] : null;
    }

    private bool FilteredOut(string name) => _filter is not null && !name.Contains(_filter, StringComparison.Ordinal);

    public void Test(string name, Action body, bool skip = false, int timeoutMs = DefaultTimeoutMs)
    {
        if (FilteredOut(name))
        {
            return;
        }

        if (skip)
        {
            Console.WriteLine($"SKIP  {name}");
            _skipped++;
            return;
        }

        try
        {
            RunWithWatchdog(name, body, timeoutMs);
            Console.WriteLine($"PASS  {name}");
            _passed++;
        }
        catch (Exception e)
        {
            Console.WriteLine($"FAIL  {name}: {e.Message}");
            _failed++;
        }
        finally
        {
            // Servers do not outlive the test that started them. Each holds a thread, a port and
            // its descriptors, and a long suite that left them up would end with dozens of reactors
            // competing for the box - the tests that notice are whichever ones happen to be
            // timing-sensitive, which makes it look like a bug in whatever they were testing.
            TestServer.StopAll();
        }
    }

    /// <summary>
    /// A test that is EXPECTED to fail, because it reproduces a defect that has not been fixed yet.
    /// It reports PEND while it still fails, and FAILS the run the moment it starts passing.
    /// </summary>
    /// <param name="because">
    /// Why it fails, and where that is being tracked - an issue number, or the finding it came from.
    /// This is the whole value of the entry, so it is required rather than optional.
    /// </param>
    /// <remarks>
    /// This exists so that "I found a bug" and "I fixed a bug" can be separate pieces of work
    /// without either one being lost. A finding described in prose is a claim; a test that
    /// reproduces it is evidence, and the difference between the two is most of what a review is
    /// worth.
    ///
    /// The inversion is deliberate: a PEND that starts passing is a FAILURE, not a quiet success.
    /// Something changed the behaviour, and either the defect is fixed - in which case this becomes
    /// an ordinary Test and stops being able to regress - or it was masked, which is worth knowing
    /// immediately rather than whenever somebody next reads the file.
    /// </remarks>
    public void Pending(string name, Action body, string because, int timeoutMs = DefaultTimeoutMs)
    {
        if (FilteredOut(name))
        {
            return;
        }

        try
        {
            RunWithWatchdog(name, body, timeoutMs);
        }
        catch (Exception)
        {
            // Failed, as expected. The reason is printed rather than the exception: what matters is
            // WHY this is known to fail, and the exception is just today's symptom of it.
            Console.WriteLine($"PEND  {name}  ({because})");
            _pending++;
            return;
        }
        finally
        {
            TestServer.StopAll();
        }

        Console.WriteLine(
            $"FAIL  {name}: expected to fail ({because}), but it PASSED - if the defect is fixed, "
            + "make this a Test() so it can never regress; if it was masked, find out what masked it");
        _failed++;
    }

    /// <summary>
    /// A test that fails against today's epoxide core because of a core bug that has been reported
    /// to the core's owner and not fixed yet. Listed as KNOWN and NOT run, so the suite stays green;
    /// <see cref="KnownCoreBugs.Run"/> runs every one of them as an ordinary <see cref="Test"/>.
    /// </summary>
    /// <param name="bug">The bug's id and one line on it, as the report that came with the test names it.</param>
    /// <remarks>
    /// Not <see cref="Pending"/>, which wants a tracked issue and runs its body: some of these hang a
    /// caller or strand a descriptor for the rest of the process, which a green run cannot absorb.
    /// Once the core is fixed, flip the switch, watch them pass, and make each one a Test().
    /// </remarks>
    public void KnownCoreBug(string name, Action body, string bug, int timeoutMs = DefaultTimeoutMs)
    {
        if (FilteredOut(name))
        {
            return;
        }

        if (KnownCoreBugs.Run)
        {
            Test($"{name} [{bug}]", body, timeoutMs: timeoutMs);
            return;
        }

        Console.WriteLine($"KNOWN {name}  ({bug}; EPOXIDE_KNOWN_CORE_BUGS=run runs it)");
        _knownBugs++;
    }

    /// <summary>
    /// Run the body on a worker and give up on it after <paramref name="timeoutMs"/>. Test bodies
    /// are synchronous, so one that wedges - a read that never completes, an acquire that never
    /// resolves - would otherwise hang the whole suite and report nothing at all. A hung test is
    /// now one FAIL and the rest still run.
    /// </summary>
    /// <remarks>
    /// The worker is abandoned rather than aborted, because .NET cannot abort a thread and killing
    /// a reactor mid-operation would corrupt every later test anyway. It is a background thread, so
    /// it cannot keep the process alive past the summary.
    /// </remarks>
    private static void RunWithWatchdog(string name, Action body, int timeoutMs)
    {
        Exception? failure = null;
        using var finished = new ManualResetEventSlim(false);

        var worker = new Thread(() =>
        {
            try
            {
                body();
            }
            catch (Exception e)
            {
                failure = e;
            }
            finally
            {
                finished.Set();
            }
        })
        {
            IsBackground = true,
            Name = $"test-{name}",
        };
        worker.Start();

        if (!finished.Wait(timeoutMs))
        {
            throw new TimeoutException(
                $"timed out after {timeoutMs} ms (the test is wedged; later tests still ran)");
        }

        if (failure is not null)
        {
            // Capture/Throw, not `throw failure` - the latter resets the stack to this line, which
            // discards where the test actually broke.
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    public int Summary()
    {
        // A reactor can die after the test that started it has already passed - in a ticker, a
        // sweep, a later handler - and every assertion still succeeds. Reporting green in that case
        // would hide it, so any death nobody consumed fails the run here.
        IReadOnlyList<string> unreported = TestServer.DrainUnreportedFailures();
        foreach (string failure in unreported)
        {
            Console.WriteLine($"FAIL  a test reactor died and no test observed it: {failure}");
            _failed++;
        }

        string pending = _pending > 0 ? $", {_pending} pending" : "";
        string known = _knownBugs > 0 ? $", {_knownBugs} known core bugs not run" : "";
        Console.WriteLine($"\n{_passed} passed, {_failed} failed, {_skipped} skipped{pending}{known}");
        return _failed == 0 ? 0 : 1;
    }
}

/// <summary>
/// The switch for the tests registered with <see cref="Runner.KnownCoreBug"/>: tests that reproduce
/// a reported epoxide core bug and stay out of the green run until it is fixed.
/// </summary>
public static class KnownCoreBugs
{
    /// <summary>
    /// <c>EPOXIDE_KNOWN_CORE_BUGS=run</c> runs them as ordinary tests - red until the core is fixed,
    /// green after, at which point each becomes a Test().
    /// </summary>
    public static bool Run { get; } =
        string.Equals(Environment.GetEnvironmentVariable("EPOXIDE_KNOWN_CORE_BUGS"), "run", StringComparison.Ordinal);
}

public static class Assert
{
    public static void Equal<T>(T expected, T actual)
    {
        if (!Equals(expected, actual))
        {
            throw new Exception($"expected [{expected}], got [{actual}]");
        }
    }

    public static void True(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception(message);
        }
    }

    /// <summary>
    /// Runs <paramref name="action"/> and requires it to throw <typeparamref name="T"/>, optionally
    /// with <paramref name="because"/> somewhere in the message.
    /// </summary>
    /// <remarks>
    /// The reason to pass a fragment: a test that only asserts "it threw" passes when something
    /// else entirely went wrong - a port already bound, a reactor that died - and reports the
    /// refusal it was looking for. Naming the reason is what makes the test about the reason.
    /// </remarks>
    public static void Throws<T>(Action action, string? because = null) where T : Exception
    {
        try
        {
            action();
        }
        catch (T e)
        {
            if (because is not null && !e.Message.Contains(because))
            {
                throw new Exception($"threw {typeof(T).Name} as expected, but for the wrong reason: {e.Message}");
            }

            return;
        }
        catch (Exception e)
        {
            throw new Exception($"expected {typeof(T).Name}, got {e.GetType().Name}: {e.Message}");
        }

        throw new Exception($"expected {typeof(T).Name}{(because is null ? "" : $" ({because})")}, but nothing was thrown");
    }
}
