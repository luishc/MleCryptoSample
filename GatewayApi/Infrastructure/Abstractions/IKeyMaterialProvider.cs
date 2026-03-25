using System.Security.Cryptography;

namespace GatewayApi.Infrastructure.Abstractions;

public interface IKeyMaterialProvider
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    // Gateway own keys
    ECDsa GetGatewaySigPrivate();
    CngKey GetGatewayEncPrivate(string kid);
    string GetGatewaySigKid();
    string GetGatewayEncKid();

    // Client public keys per merchant (current + previous during rotation window)
    IReadOnlyDictionary<string, ECDsa> GetClientSigPublicByKid(string merchantId);
    IReadOnlyDictionary<string, CngKey> GetClientEncPublicByKid(string merchantId);
}

