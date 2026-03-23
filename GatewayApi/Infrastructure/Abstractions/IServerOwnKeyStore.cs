using GatewayApi.Models;
using System.Security.Cryptography;

namespace GatewayApi.Infrastructure.Abstractions
{
    public interface IServerOwnKeyStore
    {
        DiscoveryKeysDto GetDiscoveryKeys();
        ECDsa GetJwsPrivate();
        CngKey GetEncPrivate();
        string GetCurrentSigKid();
        string GetCurrentEncKid();
        IReadOnlyCollection<JwkKey> GetJwkKeys();
    }
}