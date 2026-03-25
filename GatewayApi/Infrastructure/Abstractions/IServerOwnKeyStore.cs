using System.Security.Cryptography;

namespace GatewayApi.Infrastructure.Abstractions
{
    public interface IServerOwnKeyStore
    {
        ECDsa GetJwsPrivate();
        CngKey GetEncPrivate();
        string GetCurrentSigKid();
        string GetCurrentEncKid();
    }
}