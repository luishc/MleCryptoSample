using System.Security.Cryptography;

namespace GatewayApi.Infrastructure.Abstractions;

public interface IKeyMaterialProvider
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    // Gateway own keys
    ECDsa GetGatewaySigPrivate();
    CngKey GetGatewayEncPrivate();
    string GetGatewaySigKid();
    string GetGatewayEncKid();

    // Client public keys per merchant (single active keypair per merchant)
    ECDsa GetClientSigPublic(string merchantId);
    CngKey GetClientEncPublic(string merchantId);
    string GetClientSigKid(string merchantId);
    string GetClientEncKid(string merchantId);
}

