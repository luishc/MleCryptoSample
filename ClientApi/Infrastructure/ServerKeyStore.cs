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
        var expected = _provider.GetGatewaySigKid();
        if (!string.Equals(kid, expected, StringComparison.Ordinal))
            throw new InvalidOperationException($"kid inválido do gateway. Esperado '{expected}'.");
        return _provider.GetGatewaySigPublic();
    }

    public CngKey GetServerEncPublic(string kid)
    {
        var expected = _provider.GetGatewayEncKid();
        if (!string.Equals(kid, expected, StringComparison.Ordinal))
            throw new InvalidOperationException($"kid inválido do gateway. Esperado '{expected}'.");
        return _provider.GetGatewayEncPublic();
    }
}

