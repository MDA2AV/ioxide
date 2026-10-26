# ioxide

[![nuget](https://img.shields.io/nuget/v/ioxide?label=nuget&color=blue)](https://www.nuget.org/packages/ioxide/)
[![HTTP Arena](https://img.shields.io/endpoint?url=https://www.http-arena.com/badge/genhttp-ioxide/h1.json)](https://www.http-arena.com/#sort=rps:-1)
[![net](https://img.shields.io/badge/.NET-10%20%7C%2011-blue)](https://dotnet.microsoft.com/)
[![linux](https://img.shields.io/badge/linux-6.1%2B-blue)](https://kernel.org/)

**A shared-nothing io_uring runtime for .NET.** One reactor per core, each with its own ring, and
handlers are plain `async` code that always resumes on its reactor.

> Linux 6.1+ · .NET 10 / .NET 11 · experimental

```bash
dotnet add package ioxide
```

HTTP/2, HTTP/3, QUIC, the clients and the ASP.NET Core transport are separate `ioxide.*` packages.

- **[Documentation](https://mda2av.github.io/ioxide/)**: guides and runnable examples.
- **[Playground](Playground/)**: one complete server per workload, ready to copy and run.

Each reactor locks about 1 MB of memory, so raise `ulimit -l` if a server with many reactors won't start.
