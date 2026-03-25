using System.Security.Cryptography;

namespace ClientApi.Infrastructure.Abstractions;

public interface IClientKeyMaterialProvider
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    // Client own keys
    ECDsa GetClientSigPrivate();
    CngKey GetClientEncPrivate();
    string GetClientSigKid();
    string GetClientEncKid();

    // Gateway public keys (single active keypair)
    ECDsa GetGatewaySigPublic();
    CngKey GetGatewayEncPublic();
    string GetGatewaySigKid();
    string GetGatewayEncKid();
}

