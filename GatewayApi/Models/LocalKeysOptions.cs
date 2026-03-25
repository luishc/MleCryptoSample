namespace GatewayApi.Models;

public sealed class LocalKeysOptions
{
    public required GatewayLocalKeysOptions Gateway { get; init; }
    public required Dictionary<string, MerchantLocalKeysOptions> Merchants { get; init; }
}

public sealed class GatewayLocalKeysOptions
{
    public required string SigKid { get; init; }
    public required string EncKid { get; init; }

    /// <summary>PKCS#8 PEM (-----BEGIN PRIVATE KEY-----) ou EC PRIVATE KEY PEM.</summary>
    public required string SigPrivateKeyPem { get; init; }

    /// <summary>PKCS#8 PEM (-----BEGIN PRIVATE KEY-----) ou EC PRIVATE KEY PEM.</summary>
    public required string EncPrivateKeyPem { get; init; }
}

public sealed class MerchantLocalKeysOptions
{
    public required string SigKid { get; init; }
    public required string EncKid { get; init; }

    /// <summary>PEM da chave pública EC (SPKI) do cliente para assinatura.</summary>
    public required string SigPublicKeyPem { get; init; }

    /// <summary>PEM da chave pública EC (SPKI) do cliente para ECDH.</summary>
    public required string EncPublicKeyPem { get; init; }
}

