namespace ClientApi.Models;

public sealed class LocalClientKeysOptions
{
    public required ClientLocalKeysOptions Client { get; init; }
    public required GatewayLocalPublicKeysOptions Gateway { get; init; }
}

public sealed class ClientLocalKeysOptions
{
    public required string SigKid { get; init; }
    public required string EncKid { get; init; }
    public required string SigPrivateKeyPem { get; init; }
    public required string EncPrivateKeyPem { get; init; }
}

public sealed class GatewayLocalPublicKeysOptions
{
    public required string SigKid { get; init; }
    public required string EncKid { get; init; }
    public required string SigPublicKeyPem { get; init; }
    public required string EncPublicKeyPem { get; init; }
}

