namespace ioxide.grpc;

/// <summary>Knobs for <see cref="GrpcServices"/>, shared by every call it serves.</summary>
public sealed record GrpcOptions
{
    /// <summary>
    /// Largest request message accepted, in bytes; a bigger one ends its call with RESOURCE_EXHAUSTED.
    /// 4 MiB, gRPC's own default.
    /// </summary>
    public int MaxReceiveMessageSize { get; init; } = 4 * 1024 * 1024;

    /// <summary>
    /// Put the exception's type and message in the status of a call whose method threw something
    /// other than an RpcException. Off by default: that detail reaches the client.
    /// </summary>
    public bool EnableDetailedErrors { get; init; }
}
