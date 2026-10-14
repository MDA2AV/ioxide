# fuzz

Randomised and long-running checks that do not belong in `tests/`.

The line between the two is what a failure means. A test in `tests/` states a claim and either
holds or does not, in seconds, on every run - that is why it can gate a merge. What is here asks a
different question: *does anything break against input nobody wrote by hand, or after this runs for
a very long time?* It is not deterministic, it takes minutes to hours, and a green run proves only
that this run was green. Gating a merge on that would be a lie.

It is also not the same job as `Ioxide.Tests.Chaos`. That suite holds 47 hostile inputs someone
**thought of** - a truncated frame, a header past the limit, a body that lies about its length -
and it is deterministic and fast for exactly that reason. The value here is the input nobody
thought of, which only shows up after a few hundred million attempts.

**A finding here is not a finding until it is a test.** When something breaks, the input or the
sequence goes into `tests/` as an ordinary case - named, minimal, deterministic - and this keeps
the raw artefact only as a seed. Every run prints the seed it used, so a failure is re-runnable
byte for byte.

```bash
dotnet run -c Release --project fuzz/Ioxide.Fuzz              # the parsers, 2m per target
dotnet run -c Release --project fuzz/Ioxide.Fuzz qpack 300    # one target, longer
bash fuzz/soak/churn.sh 200000                                # connection churn
bash fuzz/soak/datagram-flood.sh                              # hostile datagrams
bash fuzz/shim/build.sh && fuzz/shim/build/fuzz_client_hello  # the one C parser
```

## `Ioxide.Fuzz/` - the managed parsers

This is where ioxide's parsing lives, so this is where most of the effort goes. The QUIC transport
is vendored ngtcp2 and the TLS is BoringSSL or picotls, so the hand-written attack surface is small
and almost all of it is C#: HTTP/3 varints, QPACK prefixed integers, and whole QPACK field sections
decoded straight into the request object a handler is then handed.

The oracle is not "did not throw". These are `Try*` parsers whose contract is to **return false**
on bad input, so an exception escaping one is the bug. Each target also checks the invariant that
makes a silent parser bug visible - chiefly that `consumed` never exceeds what was handed in, which
is what a length that wrapped or a loop that failed to advance looks like from outside.

Purely random bytes bounce off the first length check, so the QPACK target alternates: half random,
half a well-formed field section with a few bytes flipped and sometimes truncated. That is what
reaches the string and Huffman paths rather than the front door.

## `soak/` - the whole server, for a long time

`churn.sh` drives reconnects through `h3x --reconnect`. Connection setup and teardown is where a
QUIC server leaks - a connection id route that outlives its connection, a native handle nothing
frees, a timer still firing on a connection already gone - and one request proves none of it. It
reports RSS either side of ten thousand connections and then asks for one more request, because a
transport that quietly stopped routing looks exactly like a healthy idle one.

`datagram-flood.sh` fires malformed, truncated and plausible-but-wrong datagrams at a live sample
and then asks it to serve a real request. Same assertion, same reason.

## `shim/` - the one hand-written parser in C

`iq_count_host_names` walks a raw ClientHello counting `server_name` entries, because picotls does
not enforce RFC 6066's "at most one name of a type" and overwrites instead - the last name wins, so
anything in front reading the first (an SNI router, an ACL) would have been looking at a different
host than the one this server answers for. It reads a length-prefixed structure four levels deep
from bytes chosen by whoever connected, in a language that will not bounds-check it. That earns a
fuzzer; the rest of the shim is thin marshalling over the vendored libraries and does not.

The harness does not copy the function. `build.sh` extracts it from the shim at build time and
fails if it cannot find it, so there is one source of truth and moving it is loud rather than
silent. With `clang` it builds a libFuzzer target; without it - this machine has none - it builds
a standalone driver under ASan and UBSan that replays `corpus/` and then sweeps structure-aware
random input. Both entry points call the same function.
