namespace GatewayApi.Models;

// Discovery endpoints descontinuados: este DTO permanece apenas para compatibilidade binária
// com eventuais consumers internos, mas não é mais usado pelo gateway.
public sealed class DiscoveryKeysDto
{
    public required string JwsPublicKey { get; init; }
    public required string EncX { get; init; }
    public required string EncY { get; init; }
}