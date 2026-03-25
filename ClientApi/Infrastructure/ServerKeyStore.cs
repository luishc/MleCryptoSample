using ClientApi.Infrastructure.Abstractions;
using System.Security.Cryptography;

namespace ClientApi.Infrastructure;

public sealed class ServerKeyStore : IServerKeyStore
{
    private readonly IClientKeyMaterialProvider _provider;

    public ServerKeyStore(IClientKeyMaterialProvider provider)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    public string GetCurrentSigKid() => _provider.GetGatewaySigKid();
    public string GetCurrentEncKid() => _provider.GetGatewayEncKid();

    public ECDsa GetServerJwsPublic(string kid)
    {
        return _provider.GetGatewaySigPublic(kid);
    }

    public CngKey GetServerEncPublic(string kid)
    {
        return _provider.GetGatewayEncPublic(kid);
    }
}

