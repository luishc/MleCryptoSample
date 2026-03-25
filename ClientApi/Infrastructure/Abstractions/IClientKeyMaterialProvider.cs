using System.Security.Cryptography;

namespace ClientApi.Infrastructure.Abstractions;

public interface IClientKeyMaterialProvider
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    // Client own keys
    ECDsa GetClientSigPrivate();
    CngKey GetClientEncPrivate(string kid);
    string GetClientSigKid();
    string GetClientEncKid();

    // Gateway public keys (current + previous during rotation window)
    ECDsa GetGatewaySigPublic(string kid);
    CngKey GetGatewayEncPublic(string kid);
    string GetGatewaySigKid();
    string GetGatewayEncKid();
}

