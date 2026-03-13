using System.Security.Cryptography;

namespace GatewayApi.Infrastructure.Abstractions
{
    public interface IClientKeyStore
    {
        Task EnsureInitializedAsync(string merchantId, string discoveryUrl);
        ECDsa GetClientJwsPublic(string merchantId);
        CngKey GetClientEncPublic(string merchantId);
    }
}