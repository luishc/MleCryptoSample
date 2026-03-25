using ClientApi.Infrastructure.Abstractions;
using System.Security.Cryptography;

namespace ClientApi;

public interface IClientOwnKeyStore
{
    ECDsa GetJwsPrivate();
    CngKey GetEncPrivate(string kid);
    string GetCurrentSigKid();
    string GetCurrentEncKid();
}

public sealed class ClientOwnKeyStore : IClientOwnKeyStore
{
    private readonly IClientKeyMaterialProvider _provider;

    public ClientOwnKeyStore(IClientKeyMaterialProvider provider)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    public ECDsa GetJwsPrivate() => _provider.GetClientSigPrivate();
    public CngKey GetEncPrivate(string kid) => _provider.GetClientEncPrivate(kid);
    public string GetCurrentSigKid() => _provider.GetClientSigKid();
    public string GetCurrentEncKid() => _provider.GetClientEncKid();
}
