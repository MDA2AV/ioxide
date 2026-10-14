# One image per sample. Build from the repo root, naming the sample directory:
#
#   docker build -f Playground/Dockerfile --build-arg SAMPLE=Tcp/Raw -t playground-raw .
#   docker run --rm -p 8080:8080 playground-raw
#
#   docker build -f Playground/Dockerfile --build-arg SAMPLE=Http3/Nghttp3Request -t playground-h3 .
#   docker run --rm -p 8080:8080 -p 8443:8443/udp playground-h3
#
# SAMPLE is the directory path under Playground/ - any directory that carries a csproj:
# Tcp/Raw, Tcp/Pipe, Tls/OpenSsl, Http2/Nghttp2, Http3/Nghttp3Request, Clients/Pg, Proxy/H1ToH1, ...
ARG SAMPLE=Tcp/Raw

FROM mcr.microsoft.com/dotnet/sdk:11.0-preview AS build
ARG SAMPLE
WORKDIR /src

# global.json pins the SDK feature band, and every package csproj references the root README.md
# via <None Include="../../../README.md" />, so both have to be in place before restore.
COPY global.json README.md ./

# The whole source tree in one layer. Listing each csproj first would cache the restore layer, but
# with 20+ projects that list rots every time one is added - correctness over a cold restore here.
# src/ also carries the committed runtimes/linux-x64/native/*.so bundles, which the ngtcp2 and
# nghttp3 projects copy next to the output so DllImport probing finds them.
COPY src/ src/
COPY Playground/ Playground/

# Publish just the requested sample; project references pull in only what it actually needs.
# The csproj is discovered rather than spelled out, because SAMPLE may contain a directory
# separator (Tcp/Raw) while the assembly it produces is dotted (Playground.Tcp.Raw). The symlink
# then gives the final stage a fixed exec-form entrypoint despite the varying assembly name.
RUN csproj="$(ls Playground/${SAMPLE}/*.csproj)" \
 && dotnet publish "$csproj" -c Release -o /app \
 && ln -s "/app/$(basename "$csproj" .csproj)" /app/playground

# The native bundles (BoringSSL, ngtcp2, nghttp2, nghttp3) depend on nothing beyond libc; the runtime
# image's own OpenSSL is .NET's, for its crypto APIs.
FROM mcr.microsoft.com/dotnet/runtime:11.0-preview
WORKDIR /app
COPY --from=build /app .

ENV PLAYGROUND_REACTORS=1
EXPOSE 8080/tcp
EXPOSE 8443/udp

# Exec form, so the sample is PID 1 and SIGTERM reaches it - the HTTP/3 samples GOAWAY their live
# connections on that signal rather than dropping them mid-request.
ENTRYPOINT ["/app/playground"]
